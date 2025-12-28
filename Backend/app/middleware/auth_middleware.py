"""Authentication middleware for JWT, API Key, and OAuth2 (Postgres + SQLAlchemy)."""
from __future__ import annotations

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from typing import Optional, List
from functools import wraps
from datetime import datetime, timezone
import logging

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.utils.security import decode_token, hash_api_key
from app.schemas.auth import UserRole

# Update these imports to match your project structure
from app.database import get_db
from app.models.app_client import AppClient, APIKey
from app.models.subscription import Subscription


logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class AuthContext:
    """Context object holding authentication information."""
    def __init__(
        self,
        auth_type: str,  # "jwt", "api_key", "oauth_client"
        identity_id: str,
        identity_type: str,  # "user", "app_client"
        email: Optional[str] = None,
        role: Optional[UserRole] = None,
        org_id: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        app_client_id: Optional[str] = None,
    ):
        self.auth_type = auth_type
        self.identity_id = identity_id
        self.identity_type = identity_type
        self.email = email
        self.role = role
        self.org_id = org_id
        self.scopes = scopes or []
        self.app_client_id = app_client_id

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def has_any_scope(self, scopes: List[str]) -> bool:
        return any(s in self.scopes for s in scopes)

    def has_all_scopes(self, scopes: List[str]) -> bool:
        return all(s in self.scopes for s in scopes)


# ---------- JWT (make it "optional") ----------

async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[AuthContext]:
    """
    Try to authenticate via JWT bearer token.
    Returns None if missing/invalid, so API-key auth can still work.
    """
    if not credentials:
        return None

    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        return None

    token_type = payload.get("type")
    if token_type not in ["access", "oauth_client"]:
        return None

    if token_type == "oauth_client":
        sub = payload.get("sub")
        if not sub:
            return None
        return AuthContext(
            auth_type="oauth_client",
            identity_id=sub,
            identity_type="app_client",
            scopes=payload.get("scopes", []),
            app_client_id=sub,
        )

    # user JWT
    sub = payload.get("sub")
    role = payload.get("role")
    if not sub or not role:
        return None

    try:
        user_role = UserRole(role)
    except Exception:
        return None

    return AuthContext(
        auth_type="jwt",
        identity_id=sub,
        identity_type="user",
        email=payload.get("email"),
        role=user_role,
        org_id=payload.get("org_id"),
    )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> AuthContext:
    """
    Strict version for endpoints that REQUIRE JWT user auth.
    """
    ctx = await get_current_user_optional(request, credentials)
    if not ctx:
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token")
    if ctx.identity_type != "user":
        raise HTTPException(status_code=403, detail="User authentication required")
    return ctx


# ---------- API key auth (Postgres) ----------

async def get_api_key_client(
    request: Request,
    db: AsyncSession = Depends(get_db),
    api_key: Optional[str] = Depends(api_key_header),
) -> Optional[AuthContext]:
    """
    Validate API key and return app client context.
    Returns None if no API key provided.
    """
    if not api_key:
        return None

    key_hash = hash_api_key(api_key)

    # 1) load key
    key_row = (
        await db.execute(
            select(APIKey).where(APIKey.key_hash == key_hash)
        )
    ).scalars().first()

    if not key_row:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not getattr(key_row, "is_active", False):
        raise HTTPException(status_code=401, detail="API key is revoked")

    # 2) expiration
    expires_at = getattr(key_row, "expires_at", None)
    if expires_at and expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="API key has expired")

    # 3) load app client
    app_client = (
        await db.execute(
            select(AppClient).where(AppClient.id == key_row.app_client_id)
        )
    ).scalars().first()

    if not app_client or not getattr(app_client, "is_active", False):
        raise HTTPException(status_code=401, detail="App client is inactive")

    # 4) fetch approved subscriptions scopes
    subs = (
        await db.execute(
            select(Subscription.granted_scopes).where(
                Subscription.app_client_id == app_client.id,
                Subscription.status == "approved",
            )
        )
    ).all()

    all_scopes: List[str] = []
    for (scopes_val,) in subs:
        if not scopes_val:
            continue
        # granted_scopes can be list/array/json
        all_scopes.extend(list(scopes_val))

    # 5) update last_used_at (use flush/commit depending on your txn strategy)
    try:
        await db.execute(
            update(APIKey)
            .where(APIKey.id == key_row.id)
            .values(last_used_at=datetime.now(timezone.utc))
        )
        await db.commit()
    except Exception:
        await db.rollback()
        logger.exception("Failed updating api key last_used_at")

    return AuthContext(
        auth_type="api_key",
        identity_id=str(key_row.id),
        identity_type="app_client",
        org_id=getattr(app_client, "org_id", None),
        scopes=sorted(set(all_scopes)),
        app_client_id=str(app_client.id),
    )


async def get_auth_context(
    request: Request,
    jwt_auth: Optional[AuthContext] = Depends(get_current_user_optional),
    api_key_auth: Optional[AuthContext] = Depends(get_api_key_client),
) -> AuthContext:
    """
    Get authentication context from either JWT or API key.
    Prefers JWT if both provided.
    """
    if jwt_auth:
        return jwt_auth
    if api_key_auth:
        return api_key_auth
    raise HTTPException(status_code=401, detail="Authentication required")


# ---------- RBAC / scope dependencies ----------

def require_role(*roles: UserRole):
    """Decorator to require specific user roles."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            auth = kwargs.get("auth") or kwargs.get("current_user")
            if not auth:
                raise HTTPException(status_code=401, detail="Authentication required")

            if auth.identity_type != "user":
                raise HTTPException(status_code=403, detail="This endpoint requires user authentication")

            if auth.role not in roles:
                raise HTTPException(status_code=403, detail=f"Required role: {[r.value for r in roles]}")

            return await func(*args, **kwargs)
        return wrapper
    return decorator


def verify_scopes(required_scopes: List[str]):
    """Dependency to verify required scopes."""
    async def scope_checker(auth: AuthContext = Depends(get_auth_context)):
        if not auth.has_all_scopes(required_scopes):
            raise HTTPException(status_code=403, detail=f"Missing required scopes: {required_scopes}")
        return auth
    return scope_checker


class RoleChecker:
    """Dependency class for role-based access control."""
    def __init__(self, allowed_roles: List[UserRole]):
        self.allowed_roles = allowed_roles

    async def __call__(self, auth: AuthContext = Depends(get_current_user)) -> AuthContext:
        if auth.identity_type != "user":
            raise HTTPException(status_code=403, detail="This endpoint requires user authentication")

        if auth.role not in self.allowed_roles:
            raise HTTPException(status_code=403, detail=f"Required role: {[r.value for r in self.allowed_roles]}")
        return auth
