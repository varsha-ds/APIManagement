"""
Admin routes for platform administration (Postgres + SQLAlchemy).

Assumptions:
- Using sync SQLAlchemy SessionLocal and Depends(get_db)
- RoleChecker returns AuthContext and enforces platform_admin
- audit_log and audit_logger are available (ideally sync)
"""

from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from app.database import get_db

from app.schemas.auth import UserRole
from app.models.auth import User
from app.models.organization import Organization
from app.models.api_management import APIProduct, APIVersion
from app.models.app_client import AppClient, APIKey
from app.models.subscription import Subscription

from app.middleware.auth_middleware import AuthContext, RoleChecker
from app.middleware.rate_limiter import rate_limiter
from app.middleware.audit_log import audit_logger, audit_log

from app.database import get_db

from app.schemas.audit_log import AuditLogResponse

router = APIRouter(prefix="/admin", tags=["Platform Administration"])


class SetupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    action: Optional[str] = None,
    decision: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Query audit logs (platform admin only).
    """
    logs = audit_logger.get_logs(
        db=db,
        actor_id=actor_id,
        resource_type=resource_type,
        action=action,
        decision=decision,
        limit=limit,
        offset=offset,
    )
    return logs


@router.get("/rate-limits/{key}")
def get_rate_limit_stats(
    key: str,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
):
    """Get rate limit statistics for a key (platform admin only)."""
    return rate_limiter.get_stats(key)


@router.delete("/rate-limits/{key}")
def reset_rate_limit(
    key: str,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
):
    """Reset rate limit for a key (platform admin only)."""
    rate_limiter.reset(key)

    audit_log(
        action="admin.rate_limit.reset",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="rate_limit",
        resource_id=key,
        request=request,
    )

    return {"message": f"Rate limit reset for key: {key}"}


@router.post("/setup")
def initial_setup(
    data: SetupRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Initial platform setup - creates first platform admin.
    This endpoint only works if no users exist in the system.
    """
    # "Setup only once" check
    existing_user = db.query(User.id).limit(1).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Setup already completed. Users already exist in the system.",
        )

    # Import service here to avoid circular imports
    from app.services.auth_service import AuthService

    auth_service = AuthService(db)

    try:
        user = auth_service.create_platform_admin(
            email=str(data.email),
            password=data.password,
            name=data.name,
        )

        audit_log(
            action="admin.setup",
            actor_id=str(user.id),
            actor_type="system",
            resource_type="platform",
            resource_id="initial_setup",
            request=request,
        )

        # Return a safe user payload (no password_hash)
        return {
            "message": "Platform setup complete. First admin user created.",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "org_id": str(user.org_id) if user.org_id else None,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
            },
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/stats")
def get_platform_stats(
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
):
    """Get platform statistics (platform admin only)."""

    # Users
    users_total = db.query(func.count(User.id)).scalar() or 0
    users_active = db.query(func.count(User.id)).filter(User.is_active.is_(True)).scalar() or 0

    # Count by role in one query
    role_counts = (
        db.query(
            func.sum(case((User.role == "platform_admin", 1), else_=0)).label("platform_admin"),
            func.sum(case((User.role == "org_admin", 1), else_=0)).label("org_admin"),
            func.sum(case((User.role == "developer", 1), else_=0)).label("developer"),
        )
        .one()
    )

    # Organizations
    org_total = db.query(func.count(Organization.id)).scalar() or 0
    org_active = db.query(func.count(Organization.id)).filter(Organization.is_active.is_(True)).scalar() or 0

    # API Products
    products_total = db.query(func.count(APIProduct.id)).scalar() or 0
    products_active = db.query(func.count(APIProduct.id)).filter(APIProduct.is_active.is_(True)).scalar() or 0

    # API Versions
    versions_total = db.query(func.count(APIVersion.id)).scalar() or 0
    versions_draft = db.query(func.count(APIVersion.id)).filter(APIVersion.status == "draft").scalar() or 0
    versions_published = db.query(func.count(APIVersion.id)).filter(APIVersion.status == "published").scalar() or 0
    versions_deprecated = db.query(func.count(APIVersion.id)).filter(APIVersion.status == "deprecated").scalar() or 0

    # App Clients
    clients_total = db.query(func.count(AppClient.id)).scalar() or 0
    clients_active = db.query(func.count(AppClient.id)).filter(AppClient.is_active.is_(True)).scalar() or 0

    # API Keys
    keys_total = db.query(func.count(APIKey.id)).scalar() or 0
    keys_active = db.query(func.count(APIKey.id)).filter(APIKey.is_active.is_(True)).scalar() or 0

    # Subscriptions
    subs_total = db.query(func.count(Subscription.id)).scalar() or 0
    subs_pending = db.query(func.count(Subscription.id)).filter(Subscription.status == "pending").scalar() or 0
    subs_approved = db.query(func.count(Subscription.id)).filter(Subscription.status == "approved").scalar() or 0
    subs_denied = db.query(func.count(Subscription.id)).filter(Subscription.status == "denied").scalar() or 0
    subs_revoked = db.query(func.count(Subscription.id)).filter(Subscription.status == "revoked").scalar() or 0

    return {
        "users": {
            "total": users_total,
            "active": users_active,
            "by_role": {
                "platform_admin": int(role_counts.platform_admin or 0),
                "org_admin": int(role_counts.org_admin or 0),
                "developer": int(role_counts.developer or 0),
            },
        },
        "organizations": {"total": org_total, "active": org_active},
        "api_products": {"total": products_total, "active": products_active},
        "api_versions": {
            "total": versions_total,
            "by_status": {
                "draft": versions_draft,
                "published": versions_published,
                "deprecated": versions_deprecated,
            },
        },
        "app_clients": {"total": clients_total, "active": clients_active},
        "api_keys": {"total": keys_total, "active": keys_active},
        "subscriptions": {
            "total": subs_total,
            "by_status": {
                "pending": subs_pending,
                "approved": subs_approved,
                "denied": subs_denied,
                "revoked": subs_revoked,
            },
        },
    }
