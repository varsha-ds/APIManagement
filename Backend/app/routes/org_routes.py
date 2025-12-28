"""
Organization management routes (Postgres + SQLAlchemy).

Assumptions:
- Sync SQLAlchemy session via Depends(get_db)
- OrganizationService is sync and accepts db: Session
- audit_log is sync (or has a sync wrapper)
- AuthContext has role, org_id, identity_id
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.organization import OrganizationCreate, OrganizationUpdate, OrganizationResponse
from app.schemas.auth import UserRole
from app.services.org_service import OrganizationService
from app.middleware.auth_middleware import get_current_user, AuthContext, RoleChecker
from app.middleware.audit_log import audit_log
from app.schemas.auth import UserResponse  # for org users response

router = APIRouter(prefix="/organizations", tags=["Organizations"])


def get_org_service(db: Session = Depends(get_db)) -> OrganizationService:
    return OrganizationService(db)


@router.post("", response_model=OrganizationResponse)
def create_organization(
    data: OrganizationCreate,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    org_service: OrganizationService = Depends(get_org_service),
):
    """Create a new organization (platform admin only)."""
    try:
        org = org_service.create_organization(data)

        audit_log(
            action="org.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="organization",
            resource_id=str(org.id),
            request=request,
        )
        return org
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=List[OrganizationResponse])
def list_organizations(
    is_active: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_org_service),
):
    """
    List organizations.

    - Platform admins see all organizations
    - Other users only see their own organization
    """
    if auth.role == UserRole.PLATFORM_ADMIN:
        return org_service.list_organizations(is_active=is_active, limit=limit, offset=offset)

    if auth.org_id:
        org = org_service.get_organization(auth.org_id)
        return [org] if org else []

    return []


@router.get("/{org_id}", response_model=OrganizationResponse)
def get_organization(
    org_id: UUID,
    auth: AuthContext = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_org_service),
):
    """Get organization by ID."""
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    org = org_service.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return org


@router.patch("/{org_id}", response_model=OrganizationResponse)
def update_organization(
    org_id: UUID,
    data: OrganizationUpdate,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    org_service: OrganizationService = Depends(get_org_service),
):
    """
    Update organization.

    - Platform admins can update any organization
    - Org admins can only update their own organization (except is_active)
    """
    if auth.role == UserRole.ORG_ADMIN:
        if auth.org_id != org_id:
            raise HTTPException(status_code=403, detail="Access denied")
        if data.is_active is not None:
            raise HTTPException(status_code=403, detail="Only platform admins can change organization status")

    try:
        org = org_service.update_organization(org_id, data)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        audit_log(
            action="org.update",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="organization",
            resource_id=str(org_id),
            request=request,
        )
        return org
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{org_id}")
def delete_organization(
    org_id: UUID,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    org_service: OrganizationService = Depends(get_org_service),
):
    """Deactivate organization (platform admin only)."""
    success = org_service.delete_organization(org_id)
    if not success:
        raise HTTPException(status_code=404, detail="Organization not found")

    audit_log(
        action="org.delete",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="organization",
        resource_id=str(org_id),
        request=request,
    )
    return {"message": "Organization deactivated"}


@router.post("/{org_id}/users/{user_id}")
def add_user_to_organization(
    org_id: UUID,
    user_id: UUID,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    org_service: OrganizationService = Depends(get_org_service),
):
    """Add user to organization."""
    if auth.role == UserRole.ORG_ADMIN and auth.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        success = org_service.add_user_to_org(user_id=user_id, org_id=org_id)
        if not success:
            raise HTTPException(status_code=404, detail="User not found")

        audit_log(
            action="org.add_user",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="organization",
            resource_id=str(org_id),
            details={"user_id": str(user_id)},
            request=request,
        )
        return {"message": "User added to organization"}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{org_id}/users/{user_id}")
def remove_user_from_organization(
    org_id: UUID,
    user_id: UUID,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    org_service: OrganizationService = Depends(get_org_service),
):
    """Remove user from organization."""
    if auth.role == UserRole.ORG_ADMIN and auth.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    success = org_service.remove_user_from_org(user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    audit_log(
        action="org.remove_user",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="organization",
        resource_id=str(org_id),
        details={"user_id": str(user_id)},
        request=request,
    )
    return {"message": "User removed from organization"}


@router.get("/{org_id}/users", response_model=List[UserResponse])
def get_organization_users(
    org_id: UUID,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_org_service),
):
    """Get all users in an organization."""
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return org_service.get_org_users(org_id=org_id, limit=limit, offset=offset)
