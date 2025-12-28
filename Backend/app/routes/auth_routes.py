"""
Authentication routes (Postgres + SQLAlchemy).

Assumptions:
- Sync SQLAlchemy session via Depends(get_db)
- AuthService is sync and accepts db: Session
- rate_limit_check and audit_log are sync (or have sync wrappers)
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db

from app.schemas.auth import (
    UserCreate, UserLogin, UserResponse, TokenResponse,
    RefreshTokenRequest, UserRole,
)
from app.services.auth_service import AuthService
from app.middleware.auth_middleware import get_current_user, AuthContext, RoleChecker
from app.middleware.audit_log import audit_log
from app.middleware.rate_limiter import rate_limit_check

router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_auth_service(db: Session = Depends(get_db)) -> AuthService:
    return AuthService(db)


class LoginResponse(BaseModel):
    user: UserResponse
    tokens: TokenResponse


@router.post("/register", response_model=UserResponse)
def register(
    data: UserCreate,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Register a new user.

    - Self-registration only allowed for 'developer'
    - Creating org_admin/platform_admin should be done via admin endpoint
    """
    try:
        # Rate limit registration attempts (by IP)
        ip = request.client.host if request.client else "unknown"
        rate_limit_check(f"auth:register:{ip}")

        if data.role != UserRole.DEVELOPER:
            raise HTTPException(status_code=403, detail="Can only self-register as developer")

        user = auth_service.register_user(data)

        audit_log(
            action="user.register",
            actor_id=str(user.id),
            actor_type="user",
            resource_type="user",
            resource_id=str(user.id),
            request=request,
        )

        return user

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=LoginResponse)
def login(
    data: UserLogin,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Login with email and password.
    Returns access + refresh tokens.
    """
    ip = request.client.host if request.client else "unknown"

    try:
        rate_limit_check(f"auth:login:{ip}")

        user, tokens = auth_service.login(data.email, data.password)

        audit_log(
            action="auth.login",
            actor_id=str(user.id),
            actor_type="user",
            resource_type="auth",
            resource_id=str(user.id),
            request=request,
        )

        return {"user": user, "tokens": tokens}

    except ValueError as e:
        # Log denied login attempt
        audit_log(
            action="auth.login",
            actor_id=data.email,
            actor_type="anonymous",
            resource_type="auth",
            decision="denied",
            reason=str(e),
            request=request,
        )
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    data: RefreshTokenRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Refresh access token using refresh token."""
    try:
        return auth_service.refresh_tokens(data.refresh_token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/me", response_model=UserResponse)
def get_current_user_info(
    auth: AuthContext = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Get current authenticated user info."""
    if auth.identity_type != "user":
        raise HTTPException(status_code=400, detail="This endpoint is for user authentication only")

    user = auth_service.get_user(auth.identity_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@router.get("/users", response_model=list[UserResponse])
def list_users(
    org_id: Optional[UUID] = None,
    role: Optional[UserRole] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    List users (platform admin only).
    Can filter by org and role.
    """
    return auth_service.list_users(
        org_id=org_id,
        role=role,
        limit=limit,
        offset=offset,
    )


@router.post("/users/admin", response_model=UserResponse)
def create_admin_user(
    data: UserCreate,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Create a user with any role (platform admin only).
    Use to create org_admin or other platform_admin users.
    """
    try:
        user = auth_service.register_user(data)

        audit_log(
            action="user.create_admin",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="user",
            resource_id=str(user.id),
            details={"created_role": data.role.value},
            request=request,
        )

        return user
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


class UserUpdateRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    org_id: Optional[UUID] = None
    role: Optional[UserRole] = None


@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: UUID,
    data: UserUpdateRequest,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Update user (platform admin only)."""
    user = auth_service.update_user(
        user_id=user_id,
        name=data.name,
        is_active=data.is_active,
        org_id=data.org_id,
        role=data.role,
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    audit_log(
        action="user.update",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="user",
        resource_id=str(user_id),
        request=request,
    )

    return user
