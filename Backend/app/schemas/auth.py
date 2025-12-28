from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum
from uuid import UUID


class UserRole(str, Enum):
    PLATFORM_ADMIN = "platform_admin"
    ORG_ADMIN = "org_admin"
    DEVELOPER = "developer"



class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str = Field(..., min_length=2)
    role: UserRole = UserRole.DEVELOPER




class UserLogin(BaseModel):
    email: EmailStr
    password: str




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




class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # seconds (30 minutes)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LoginResponse(BaseModel):
    user: UserResponse
    tokens: TokenResponse


class UserUpdateRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    org_id: Optional[UUID] = None
    role: Optional[UserRole] = None


class TokenPayload(BaseModel):
    sub: str  # user_id (string in JWT)
    email: EmailStr
    role: UserRole
    org_id: Optional[str] = None
    type: str  # e.g. "access" or "refresh"
    exp: datetime
    iat: datetime
