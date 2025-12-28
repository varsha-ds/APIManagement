from datetime import datetime
from enum import Enum
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class APIStatus(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"



class APIProductBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None


class APIProductCreate(APIProductBase):
    org_id: UUID 


class APIProductUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class APIProductResponse(APIProductBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID
    status: APIStatus
    is_active: bool
    created_at: datetime
    updated_at: datetime




class APIVersionBase(BaseModel):
    version: str = Field(..., pattern=r"^v\d+(\.\d+)?$")       # v1, v1.0
    base_path: str = Field(..., pattern=r"^/[a-z0-9\-/]*$")    # /orders
    description: Optional[str] = None


class APIVersionCreate(APIVersionBase):
    product_id: UUID


class APIVersionUpdate(BaseModel):
    description: Optional[str] = None
    status: Optional[APIStatus] = None


class APIVersionResponse(APIVersionBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    product_id: UUID
    status: APIStatus
    created_at: datetime
    updated_at: datetime




class ScopeBase(BaseModel):
    name: str = Field(..., pattern=r"^[a-z]+\.[a-z]+$")  # orders.read
    description: Optional[str] = None


class ScopeCreate(ScopeBase):
    product_id: UUID


class ScopeResponse(ScopeBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    product_id: UUID
    created_at: datetime




class EndpointBase(BaseModel):
    method: HTTPMethod
    path: str = Field(..., pattern=r"^/[a-zA-Z0-9\-/{}_]*$")
    summary: str
    description: Optional[str] = None


class EndpointCreate(EndpointBase):
    version_id: UUID
    # Client sends scope *names* (e.g., ["orders.read"])
    required_scopes: List[str] = Field(default_factory=list)


class EndpointUpdate(BaseModel):
    summary: Optional[str] = None
    description: Optional[str] = None
    required_scopes: Optional[List[str]] = None
    is_active: Optional[bool] = None


class EndpointResponse(EndpointBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version_id: UUID
    required_scopes: List[str] = Field(default_factory=list)
    is_active: bool
    created_at: datetime
    updated_at: datetime


class EndpointResponseDetailed(EndpointBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version_id: UUID
    required_scopes: List[ScopeResponse] = Field(default_factory=list)
    is_active: bool
    created_at: datetime
    updated_at: datetime
