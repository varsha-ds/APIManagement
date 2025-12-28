from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class OrganizationBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class OrganizationResponse(OrganizationBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    is_active: bool
    created_at: datetime
    updated_at: datetime
