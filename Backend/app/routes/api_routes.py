"""
API Management routes (Postgres + SQLAlchemy).

Assumptions:
- Sync SQLAlchemy session (SessionLocal) via Depends(get_db)
- APIService is sync and uses SQLAlchemy ORM models
- RoleChecker / get_current_user return AuthContext with:
  - identity_id (user UUID)
  - role (UserRole)
  - org_id (UUID | None)
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db

from app.schemas.api_management import (
    APIProductCreate, APIProductUpdate, APIProductResponse,
    APIVersionCreate, APIVersionUpdate, APIVersionResponse,
    EndpointCreate, EndpointUpdate, EndpointResponse,
    ScopeCreate, ScopeResponse, APIStatus,
)
from app.schemas.auth import UserRole
from app.middleware.auth_middleware import get_current_user, AuthContext, RoleChecker
from app.middleware.audit_log import audit_log
from app.services.api_service import APIService

router = APIRouter(prefix="/apis", tags=["API Management"])


def get_api_service(db: Session = Depends(get_db)) -> APIService:
    return APIService(db)


# ================== API Products ==================

@router.post("/products", response_model=APIProductResponse)
def create_api_product(
    data: APIProductCreate,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN, UserRole.DEVELOPER])),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new API product in the user's organization."""
    # If org_id is derived from auth context, your APIProductCreate should NOT include org_id.
    # If APIProductCreate includes org_id, enforce it matches auth.org_id for non-platform admins.
    if not auth.org_id and auth.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(status_code=400, detail="User must belong to an organization to create APIs")

    org_id = auth.org_id
    if auth.role == UserRole.PLATFORM_ADMIN:
        # platform admin can create in any org ONLY if payload includes org_id
        # If your schema doesn't include org_id, keep org_id required via auth context.
        org_id = getattr(data, "org_id", None) or auth.org_id

    if not org_id:
        raise HTTPException(status_code=400, detail="org_id is required to create an API product")

    try:
        product = api_service.create_product(org_id=org_id, data=data)

        audit_log(
            action="api.product.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="api_product",
            resource_id=str(product.id),
            request=request,
        )
        return product
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/products", response_model=List[APIProductResponse])
def list_api_products(
    request: Request,
    org_id: Optional[UUID] = None,
    is_active: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """List API products. Platform admins can see all; others see their org."""
    if auth.role != UserRole.PLATFORM_ADMIN:
        org_id = auth.org_id

    return api_service.list_products(
        org_id=org_id,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )


@router.get("/products/{product_id}", response_model=APIProductResponse)
def get_api_product(
    product_id: UUID,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Get API product by ID."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return product


@router.patch("/products/{product_id}", response_model=APIProductResponse)
def update_api_product(
    product_id: UUID,
    data: APIProductUpdate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Update API product."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    updated = api_service.update_product(product_id, data)

    audit_log(
        action="api.product.update",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="api_product",
        resource_id=str(product_id),
        request=request,
    )
    return updated


# ================== API Versions ==================

@router.post("/products/{product_id}/versions", response_model=APIVersionResponse)
def create_api_version(
    product_id: UUID,
    data: APIVersionCreate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new version for an API product."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        version = api_service.create_version(product_id, data)

        audit_log(
            action="api.version.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="api_version",
            resource_id=str(version.id),
            request=request,
        )
        return version
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/products/{product_id}/versions", response_model=List[APIVersionResponse])
def list_api_versions(
    product_id: UUID,
    status: Optional[APIStatus] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """List versions for an API product."""
    # Optional: enforce org access by checking product.org_id
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return api_service.list_versions(
        product_id=product_id,
        status=status,
        limit=limit,
        offset=offset,
    )


@router.get("/versions/{version_id}", response_model=APIVersionResponse)
def get_api_version(
    version_id: UUID,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Get API version by ID."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    # Enforce org access by checking parent product
    product = api_service.get_product(version.product_id)
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return version


@router.patch("/versions/{version_id}", response_model=APIVersionResponse)
def update_api_version(
    version_id: UUID,
    data: APIVersionUpdate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Update API version."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    updated = api_service.update_version(version_id, data)

    audit_log(
        action="api.version.update",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="api_version",
        resource_id=str(version_id),
        details={"status": data.status.value if data.status else None},
        request=request,
    )
    return updated


@router.post("/versions/{version_id}/publish", response_model=APIVersionResponse)
def publish_api_version(
    version_id: UUID,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Publish an API version (make it available for subscriptions)."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    updated = api_service.publish_version(version_id)

    audit_log(
        action="api.version.publish",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="api_version",
        resource_id=str(version_id),
        request=request,
    )
    return updated


@router.post("/versions/{version_id}/deprecate", response_model=APIVersionResponse)
def deprecate_api_version(
    version_id: UUID,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Deprecate an API version."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    updated = api_service.deprecate_version(version_id)

    audit_log(
        action="api.version.deprecate",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="api_version",
        resource_id=str(version_id),
        request=request,
    )
    return updated


@router.get("/versions/{version_id}/openapi")
def get_openapi_spec(
    version_id: UUID,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Generate OpenAPI specification for an API version."""
    try:
        # Enforce access (same as get version)
        version = api_service.get_version(version_id)
        if not version:
            raise HTTPException(status_code=404, detail="API version not found")
        product = api_service.get_product(version.product_id)
        if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
            raise HTTPException(status_code=403, detail="Access denied")

        return api_service.generate_openapi_spec(version_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ================== Endpoints ==================

@router.post("/versions/{version_id}/endpoints", response_model=EndpointResponse)
def create_endpoint(
    version_id: UUID,
    data: EndpointCreate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new endpoint for an API version."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        endpoint = api_service.create_endpoint(version_id, data)

        audit_log(
            action="api.endpoint.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="endpoint",
            resource_id=str(endpoint.id),
            request=request,
        )
        return endpoint
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/versions/{version_id}/endpoints", response_model=List[EndpointResponse])
def list_endpoints(
    version_id: UUID,
    is_active: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """List endpoints for an API version."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return api_service.list_endpoints(
        version_id=version_id,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )


@router.patch("/endpoints/{endpoint_id}", response_model=EndpointResponse)
def update_endpoint(
    endpoint_id: UUID,
    data: EndpointUpdate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Update an endpoint."""
    endpoint = api_service.get_endpoint(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    version = api_service.get_version(endpoint.version_id)
    product = api_service.get_product(version.product_id)
    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    updated = api_service.update_endpoint(endpoint_id, data)

    audit_log(
        action="api.endpoint.update",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="endpoint",
        resource_id=str(endpoint_id),
        request=request,
    )
    return updated


# ================== Scopes ==================

@router.post("/products/{product_id}/scopes", response_model=ScopeResponse)
def create_scope(
    product_id: UUID,
    data: ScopeCreate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new scope for an API product."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        scope = api_service.create_scope(product_id, data)

        audit_log(
            action="api.scope.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="scope",
            resource_id=str(scope.id),
            request=request,
        )
        return scope
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/products/{product_id}/scopes", response_model=List[ScopeResponse])
def list_scopes(
    product_id: UUID,
    limit: int = 100,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """List scopes for an API product."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != product.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return api_service.list_scopes(product_id=product_id, limit=limit)
