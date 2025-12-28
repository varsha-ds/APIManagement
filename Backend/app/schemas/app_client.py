"""
Pydantic schemas for App Clients + API Keys.

Rules:
- Schemas do NOT generate DB fields (id, timestamps). DB does.
- "secret shown once" behavior:
  - AppClientWithSecret returns client_secret only at creation.
  - APIKeyCreated returns api_key only at creation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


# -------------------------
# App Client
# -------------------------

class AppClientBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None


class AppClientCreate(AppClientBase):
    org_id: UUID  # if org_id comes from auth context, remove from body


class AppClientUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class AppClientResponse(AppClientBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID
    client_id: UUID
    is_active: bool
    created_at: datetime
    updated_at: datetime


class AppClientWithSecret(AppClientResponse):
    """
    Only returned once at creation time.
    Never store or re-display plaintext secret later.
    """
    client_secret: str


# -------------------------
# API Keys
# -------------------------

class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    expires_at: Optional[datetime] = None


class APIKeyUpdate(BaseModel):
    # optional future extension
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    is_active: Optional[bool] = None
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    app_client_id: UUID
    name: str
    prefix: str
    is_active: bool
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[UUID] = None


class APIKeyCreated(APIKeyResponse):
    """
    Only returned once at creation time.
    Never store or re-display plaintext api_key later.
    """
    api_key: str


class APIKeyRotate(BaseModel):
    """
    Request body for rotate.
    No fields required; endpoint action rotates.
    """
    pass


# -------------------------
# Rate limiting
# -------------------------

class RateLimitConfig(BaseModel):
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
