"""Authentication service (Postgres/SQLAlchemy)."""
from __future__ import annotations

from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime

import logging
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.schemas.auth import UserCreate, UserResponse, TokenResponse, UserRole
from app.utils.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token
)
from app.models.auth import User 

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _user_to_response(u: User) -> UserResponse:
        return UserResponse(
            id=str(u.id),
            email=u.email,
            name=u.name,
            role=u.role if isinstance(u.role, UserRole) else UserRole(u.role),
            org_id=str(u.org_id) if u.org_id is not None else None,
            is_active=u.is_active,
            created_at=u.created_at,
            updated_at=u.updated_at,
        )

    def register_user(self, user_data: UserCreate, org_id: Optional[str] = None) -> UserResponse:
        """Register a new user."""
        u = User(
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            name=user_data.name,
            role=user_data.role,      # store enum or value depending on your ORM
            org_id=org_id,
            is_active=True,
        )
        self.session.add(u)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            # unique(users.email)
            raise ValueError("Email already registered")

        self.session.refresh(u)
        return self._user_to_response(u)

    def login(self, email: str, password: str) -> Tuple[UserResponse, TokenResponse]:
        """Authenticate user and return tokens."""
        res = self.session.execute(select(User).where(User.email == email))
        u = res.scalar_one_or_none()

        if not u:
            raise ValueError("Invalid email or password")

        if not u.is_active:
            raise ValueError("Account is deactivated")

        if not verify_password(password, u.password_hash):
            raise ValueError("Invalid email or password")

        token_data = {
            "sub": str(u.id),
            "email": u.email,
            "role": (u.role.value if isinstance(u.role, UserRole) else str(u.role)),
            "org_id": str(u.org_id) if u.org_id is not None else None,
            # include token_version to support revocation of refresh tokens
            "tv": getattr(u, "token_version", 0),
        }

        return (
            self._user_to_response(u),
            TokenResponse(
                access_token=create_access_token(token_data),
                refresh_token=create_refresh_token(token_data),
            ),
        )

    def refresh_tokens(self, refresh_token: str) -> TokenResponse:
        """Refresh access token using refresh token."""
        payload = decode_token(refresh_token)

        if not payload:
            raise ValueError("Invalid or expired refresh token")
        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")

        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Invalid token payload")

        res = self.session.execute(select(User).where(User.id == user_id))
        u = res.scalar_one_or_none()

        if not u or not u.is_active:
            raise ValueError("User not found or inactive")

        # refresh token revocation check (optional but recommended)
        current_tv = getattr(u, "token_version", 0)
        if payload.get("tv", 0) != current_tv:
            raise ValueError("Invalid or expired refresh token")

        token_data = {
            "sub": str(u.id),
            "email": u.email,
            "role": (u.role.value if isinstance(u.role, UserRole) else str(u.role)),
            "org_id": str(u.org_id) if u.org_id is not None else None,
            "tv": current_tv,
        }

        return TokenResponse(
            access_token=create_access_token(token_data),
            refresh_token=create_refresh_token(token_data),
        )

    def get_user(self, user_id: str) -> Optional[UserResponse]:
        """Get user by ID."""
        res = self.session.execute(select(User).where(User.id == user_id))
        u = res.scalar_one_or_none()
        return self._user_to_response(u) if u else None

    def list_users(
        self,
        org_id: Optional[str] = None,
        role: Optional[UserRole] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[UserResponse]:
        """List users with optional filters."""
        stmt = select(User)
        if org_id:
            stmt = stmt.where(User.org_id == org_id)
        if role:
            stmt = stmt.where(User.role == role)

        stmt = stmt.order_by(User.created_at.desc()).offset(offset).limit(limit)
        res = self.session.execute(stmt)

        # Ensure password_hash is never exposed: we map to UserResponse only
        return [self._user_to_response(u) for u in res.scalars().all()]

    def update_user(
        self,
        user_id: str,
        name: Optional[str] = None,
        is_active: Optional[bool] = None,
        org_id: Optional[str] = None,
        role: Optional[UserRole] = None,
    ) -> Optional[UserResponse]:
        """Update user details."""
        values: Dict[str, Any] = {"updated_at": datetime.utcnow()}
        if name is not None:
            values["name"] = name
        if is_active is not None:
            values["is_active"] = is_active
        if org_id is not None:
            values["org_id"] = org_id
        if role is not None:
            values["role"] = role

        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(**values)
            .returning(User)
        )
        res = self.session.execute(stmt)
        row = res.fetchone()
        if not row:
            self.session.rollback()
            return None

        self.session.commit()
        return self._user_to_response(row[0])

    def revoke_refresh_tokens(self, user_id: str) -> bool:
        """
        Optional: revoke all refresh tokens by bumping token_version.
        Call this on password reset, manual logout-all, suspicious activity, etc.
        """
        if not hasattr(User, "token_version"):
            logger.warning("User.token_version not present; cannot revoke refresh tokens safely.")
            return False

        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(token_version=User.token_version + 1, updated_at=datetime.utcnow())
        )
        res = self.session.execute(stmt)
        self.session.commit()
        return res.rowcount > 0

    def create_platform_admin(self, email: str, password: str, name: str) -> UserResponse:
        """Create a platform admin user (for initial setup)."""
        user_data = UserCreate(email=email, password=password, name=name, role=UserRole.PLATFORM_ADMIN)
        return self.register_user(user_data)
