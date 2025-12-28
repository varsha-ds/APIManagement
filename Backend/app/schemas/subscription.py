from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime
from enum import Enum
from uuid import UUID


class SubscriptionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    REVOKED = "revoked"


class SubscriptionCreate(BaseModel):
    api_version_id: UUID
    app_client_id: UUID
    requested_scopes: List[str] = Field(..., min_length=1)
    justification: Optional[str] = None


class SubscriptionApprove(BaseModel):
    granted_scopes: List[str] = Field(..., min_length=1)
    rate_limit_per_minute: int = Field(default=100, ge=1, le=10000)


class SubscriptionDeny(BaseModel):
    reason: str


class SubscriptionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    app_client_id: UUID
    api_version_id: UUID
    status: SubscriptionStatus

    # Client-friendly: scope names
    requested_scopes: List[str] = Field(default_factory=list)
    granted_scopes: List[str] = Field(default_factory=list)

    rate_limit_per_minute: int = 100

    justification: Optional[str] = None
    denial_reason: Optional[str] = None

    approved_by: Optional[UUID] = None
    approved_at: Optional[datetime] = None

    created_at: datetime
    updated_at: datetime
