from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict



class AppClientBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None


class AppClientCreate(AppClientBase):
    org_id: UUID  


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
    client_secret: str




class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    expires_at: Optional[datetime] = None


class APIKeyUpdate(BaseModel): 
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
    api_key: str


class APIKeyRotate(BaseModel):
    pass


class RotateSecretResponse(BaseModel):
    client_id: UUID
    client_secret: str
    message: str




class RateLimitConfig(BaseModel):
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
