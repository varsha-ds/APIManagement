"""
Subscription routes (Postgres + SQLAlchemy).

Flow:
- Developer/Org admin requests access to an API version -> creates Subscription (PENDING)
- Org admin / Platform admin approves/denies -> status changes + granted scopes + rate limit
- Revoke -> status REVOKED, clears granted scopes optionally

Access rules (recommended baseline):
- PLATFORM_ADMIN: can view/approve/deny/revoke all
- ORG_ADMIN: can view/approve/deny/revoke within their org
- DEVELOPER: can create requests + view their org's subscriptions (or only those for their clients if you want stricter)
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db

from app.schemas.subscription import (
    SubscriptionCreate,
    SubscriptionApprove,
    SubscriptionDeny,
    SubscriptionResponse,
    SubscriptionStatus,
)
from app.schemas.auth import UserRole
from app.middleware.auth_middleware import get_current_user, AuthContext, RoleChecker
from app.middleware.audit_log import audit_log

from app.services.subscription_service import SubscriptionService
from app.services.key_service import KeyService  # to verify client belongs to org (optional but recommended)
from app.services.api_service import APIService  # to verify version/product org (recommended)

router = APIRouter(prefix="/subscriptions", tags=["Subscriptions"])


def get_subscription_service(db: Session = Depends(get_db)) -> SubscriptionService:
    return SubscriptionService(db)


def get_key_service(db: Session = Depends(get_db)) -> KeyService:
    return KeyService(db)


def get_api_service(db: Session = Depends(get_db)) -> APIService:
    return APIService(db)


# -------------------------
# Create subscription request
# -------------------------

@router.post("", response_model=SubscriptionResponse)
def create_subscription(
    data: SubscriptionCreate,
    request: Request,
    # Any authenticated user can request; enforce org presence
    auth: AuthContext = Depends(get_current_user),
    sub_service: SubscriptionService = Depends(get_subscription_service),
    api_service: APIService = Depends(get_api_service),
):
    """
    Request access to an API version (creates PENDING subscription).

    NOTE:
    We need an app_client_id to link subscription to a client. Your schema currently doesn't include it.
    You have two options:
    A) add app_client_id to SubscriptionCreate (recommended)
    B) infer a "default client" per org/user (not great)

    I'll implement A (recommended) using a service-level check.
    """
    if not auth.org_id and auth.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(status_code=400, detail="User must belong to an organization to request subscriptions")

    # Validate the API version exists and belongs to some product/org
    version = api_service.get_version(data.api_version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    # Non-platform users can only request within their org
    if auth.role != UserRole.PLATFORM_ADMIN and product.org_id != auth.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # IMPORTANT: Your SubscriptionCreate currently has no app_client_id, but subscription needs it.
    # If you haven't updated the schema yet, this will fail.
    if not hasattr(data, "app_client_id") or getattr(data, "app_client_id") is None:
        raise HTTPException(
            status_code=400,
            detail="SubscriptionCreate must include app_client_id (UUID) to link subscription to an app client",
        )

    try:
        sub = sub_service.create_subscription_request(
            app_client_id=data.app_client_id,
            api_version_id=data.api_version_id,
            requested_scope_names=data.requested_scopes,
            justification=data.justification,
            requested_by_user_id=auth.identity_id,
        )

        audit_log(
            action="subscription.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="subscription",
            resource_id=str(sub.id),
            details={"api_version_id": str(data.api_version_id)},
            request=request,
        )

        return sub

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# -------------------------
# List / get
# -------------------------

@router.get("", response_model=List[SubscriptionResponse])
def list_subscriptions(
    request: Request,
    org_id: Optional[UUID] = None,
    status: Optional[SubscriptionStatus] = None,
    api_version_id: Optional[UUID] = None,
    app_client_id: Optional[UUID] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    sub_service: SubscriptionService = Depends(get_subscription_service),
):
    """
    List subscriptions.

    - PLATFORM_ADMIN can see all (optionally filter by org_id)
    - Others can only see their org's subscriptions
    """
    if auth.role != UserRole.PLATFORM_ADMIN:
        org_id = auth.org_id
        if not org_id:
            return []

    return sub_service.list_subscriptions(
        org_id=org_id,
        status=status,
        api_version_id=api_version_id,
        app_client_id=app_client_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{subscription_id}", response_model=SubscriptionResponse)
def get_subscription(
    subscription_id: UUID,
    auth: AuthContext = Depends(get_current_user),
    sub_service: SubscriptionService = Depends(get_subscription_service),
):
    sub = sub_service.get_subscription(subscription_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    # enforce org access for non-platform admin
    if auth.role != UserRole.PLATFORM_ADMIN:
        if not auth.org_id or sub_service.get_subscription_org_id(subscription_id) != auth.org_id:
            raise HTTPException(status_code=403, detail="Access denied")

    return sub


# -------------------------
# Approve / deny / revoke
# -------------------------

@router.post("/{subscription_id}/approve", response_model=SubscriptionResponse)
def approve_subscription(
    subscription_id: UUID,
    data: SubscriptionApprove,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    sub_service: SubscriptionService = Depends(get_subscription_service),
):
    """
    Approve a subscription request.
    - ORG_ADMIN can only approve within their org
    """
    if auth.role == UserRole.ORG_ADMIN:
        org_id = sub_service.get_subscription_org_id(subscription_id)
        if not org_id or auth.org_id != org_id:
            raise HTTPException(status_code=403, detail="Access denied")

    try:
        sub = sub_service.approve_subscription(
            subscription_id=subscription_id,
            granted_scope_names=data.granted_scopes,
            rate_limit_per_minute=data.rate_limit_per_minute,
            approved_by_user_id=auth.identity_id,
        )

        if not sub:
            raise HTTPException(status_code=404, detail="Subscription not found")

        audit_log(
            action="subscription.approve",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="subscription",
            resource_id=str(subscription_id),
            details={"granted_scopes": data.granted_scopes, "rate_limit_per_minute": data.rate_limit_per_minute},
            request=request,
        )

        return sub
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{subscription_id}/deny", response_model=SubscriptionResponse)
def deny_subscription(
    subscription_id: UUID,
    data: SubscriptionDeny,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    sub_service: SubscriptionService = Depends(get_subscription_service),
):
    """
    Deny a subscription request.
    - ORG_ADMIN can only deny within their org
    """
    if auth.role == UserRole.ORG_ADMIN:
        org_id = sub_service.get_subscription_org_id(subscription_id)
        if not org_id or auth.org_id != org_id:
            raise HTTPException(status_code=403, detail="Access denied")

    sub = sub_service.deny_subscription(
        subscription_id=subscription_id,
        denial_reason=data.reason,
        approved_by_user_id=auth.identity_id,  # "decided_by"
    )
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    audit_log(
        action="subscription.deny",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="subscription",
        resource_id=str(subscription_id),
        details={"reason": data.reason},
        request=request,
    )

    return sub


@router.post("/{subscription_id}/revoke", response_model=SubscriptionResponse)
def revoke_subscription(
    subscription_id: UUID,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    sub_service: SubscriptionService = Depends(get_subscription_service),
):
    """
    Revoke an approved subscription.
    - ORG_ADMIN can only revoke within their org
    """
    if auth.role == UserRole.ORG_ADMIN:
        org_id = sub_service.get_subscription_org_id(subscription_id)
        if not org_id or auth.org_id != org_id:
            raise HTTPException(status_code=403, detail="Access denied")

    sub = sub_service.revoke_subscription(subscription_id=subscription_id, revoked_by_user_id=auth.identity_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    audit_log(
        action="subscription.revoke",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="subscription",
        resource_id=str(subscription_id),
        request=request,
    )

    return sub
