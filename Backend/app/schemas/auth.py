"""
Pydantic schemas for Authentication.

These define request/response payloads and JWT payload shapes.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum
from uuid import UUID


class UserRole(str, Enum):
    PLATFORM_ADMIN = "platform_admin"
    ORG_ADMIN = "org_admin"
    DEVELOPER = "developer"


# -------------------------
# User requests
# -------------------------

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str = Field(..., min_length=2)
    role: UserRole = UserRole.DEVELOPER

    # If org_id is derived from inviter/admin context, remove from body.
    org_id: Optional[UUID] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


# -------------------------
# User responses
# -------------------------

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    name: str
    role: UserRole
    org_id: Optional[UUID] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


# -------------------------
# Tokens
# -------------------------

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # seconds (30 minutes)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenPayload(BaseModel):
    """
    JWT claims payload shape.
    NOTE: In JWT, exp/iat are often numeric timestamps, but you can model them
    as datetime if you convert when encoding/decoding.
    """
    sub: str  # user_id (string in JWT)
    email: EmailStr
    role: UserRole
    org_id: Optional[str] = None
    type: str  # e.g. "access" or "refresh"
    exp: datetime
    iat: datetime
