"""
API Management routes (Postgres + SQLAlchemy) — permission-hardened.

Key rules implemented:
- CONTROL PLANE ONLY: user JWT required; app clients cannot access these endpoints.
- Draft visibility: only owning org (or platform admin).
- Published visibility: visible to all orgs in catalog (read-only).
- Mutations (create/update): owning org only; only while DRAFT (recommended).
- Publish/Deprecate: ORG_ADMIN or PLATFORM_ADMIN only.
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


# =========================
# Permission helpers
# =========================

def _require_org_membership(auth: AuthContext):
    if not auth.org_id and auth.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(status_code=400, detail="User must belong to an organization")


def _is_platform_admin(auth: AuthContext) -> bool:
    return auth.role == UserRole.PLATFORM_ADMIN


def _is_org_owner_or_platform(auth: AuthContext, resource_org_id: UUID) -> bool:
    if _is_platform_admin(auth):
        return True
    if not auth.org_id:
        return False
    return str(auth.org_id) == str(resource_org_id)


def _ensure_can_view_resource(auth: AuthContext, resource_org_id: UUID, status: APIStatus):
    """
    Read visibility rule:
    - PLATFORM_ADMIN: always allowed
    - Others:
      - If same org: allowed
      - If different org: only allowed if PUBLISHED
    """
    if _is_platform_admin(auth):
        return
    if auth.org_id and str(auth.org_id) == str(resource_org_id):
        return
    if status == APIStatus.PUBLISHED:
        return
    raise HTTPException(status_code=403, detail="Access denied")


def _ensure_can_mutate_owned_resource(auth: AuthContext, resource_org_id: UUID):
    """
    Mutations rule:
    - Only owning org OR platform admin (override)
    """
    if not _is_org_owner_or_platform(auth, resource_org_id):
        raise HTTPException(status_code=403, detail="Access denied")


def _ensure_draft(status: APIStatus, action: str = "modify"):
    if status != APIStatus.DRAFT:
        raise HTTPException(status_code=400, detail=f"Cannot {action} non-draft resource")


def _ensure_org_admin_or_platform(auth: AuthContext):
    if auth.role not in (UserRole.ORG_ADMIN, UserRole.PLATFORM_ADMIN):
        raise HTTPException(status_code=403, detail="Only org_admin or platform_admin allowed")


# ================== API Products ==================

@router.post("/products", response_model=APIProductResponse)
def create_api_product(
    data: APIProductCreate,
    request: Request,
    # ✅ create allowed: ORG_ADMIN + DEVELOPER (+ PLATFORM_ADMIN override)
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN, UserRole.DEVELOPER])),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new API product in DRAFT."""
    _require_org_membership(auth)

    # Platform admin can create for a specific org if schema provides org_id.
    org_id = auth.org_id
    if _is_platform_admin(auth):
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
    """
    List API products.

    Visibility:
    - PLATFORM_ADMIN: can list across orgs (org_id query param optional)
    - Others: see:
        (A) all products in their org (any status)
        (B) PUBLISHED products from other orgs (catalog visibility)
    """
    if _is_platform_admin(auth):
        return api_service.list_products(
            org_id=org_id,
            is_active=is_active,
            limit=limit,
            offset=offset,
            # optional: status filter if your service supports it
        )

    _require_org_membership(auth)

    # (A) own org products (any status)
    own = api_service.list_products(
        org_id=auth.org_id,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )

    # (B) published products from all orgs (catalog)
    # ⚠️ Requires service support for "status" filtering. If you don't have it, add it.
    published_catalog: List[APIProductResponse] = api_service.list_products(
        org_id=None,
        is_active=is_active,
        limit=limit,
        offset=offset,
        status=APIStatus.PUBLISHED,  # <-- add this param in service if missing
    )

    # Merge and de-dup by id
    seen = set()
    merged: List[APIProductResponse] = []
    for p in (own + published_catalog):
        pid = str(p.id)
        if pid not in seen:
            seen.add(pid)
            merged.append(p)

    return merged


@router.get("/products/{product_id}", response_model=APIProductResponse)
def get_api_product(
    product_id: UUID,
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Get API product by ID with draft/published visibility rules."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_view_resource(auth, product.org_id, product.status)

    return product


@router.patch("/products/{product_id}", response_model=APIProductResponse)
def update_api_product(
    product_id: UUID,
    data: APIProductUpdate,
    request: Request,
    # ✅ only users (not app clients) + must be owner org or platform
    auth: AuthContext = Depends(get_current_user),
    api_service: APIService = Depends(get_api_service),
):
    """Update API product (draft-only)."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)
    _ensure_draft(product.status, action="update product")

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
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN, UserRole.DEVELOPER])),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new version for an API product (draft-only product recommended)."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)
   

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
    """
    List versions for a product.

    Visibility:
    - Owner org: can list all statuses
    - Other orgs: only PUBLISHED versions
    - Platform admin: all
    """
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    # If user is not owner and not platform, force status=PUBLISHED
    if not _is_org_owner_or_platform(auth, product.org_id):
        status = APIStatus.PUBLISHED

    # allow view of product only if published when not owner
    _ensure_can_view_resource(auth, product.org_id, product.status)

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
    """Get API version by ID with draft/published visibility rules."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_view_resource(auth, product.org_id, version.status)

    return version


@router.patch("/versions/{version_id}", response_model=APIVersionResponse)
def update_api_version(
    version_id: UUID,
    data: APIVersionUpdate,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN, UserRole.DEVELOPER])),
    api_service: APIService = Depends(get_api_service),
):
    """Update API version (draft-only)."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)
    _ensure_draft(version.status, action="update version")

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
    # ✅ publish: ORG_ADMIN or PLATFORM_ADMIN only
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    api_service: APIService = Depends(get_api_service),
):
    """Publish an API version (make it available for subscriptions)."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)
    _ensure_draft(version.status, action="publish")

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
    # ✅ deprecate: ORG_ADMIN or PLATFORM_ADMIN only
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN])),
    api_service: APIService = Depends(get_api_service),
):
    """Deprecate an API version."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)

    # You may allow deprecate from PUBLISHED only; adjust as you like
    if version.status != APIStatus.PUBLISHED:
        raise HTTPException(status_code=400, detail="Only published versions can be deprecated")

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
    """
    Generate OpenAPI spec for an API version.

    Visibility:
    - Owner org: can view any status
    - Other orgs: only if version is PUBLISHED
    - Platform admin: all
    """
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_view_resource(auth, product.org_id, version.status)

    try:
        return api_service.generate_openapi_spec(version_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ================== Endpoints ==================

@router.post("/versions/{version_id}/endpoints", response_model=EndpointResponse)
def create_endpoint(
    version_id: UUID,
    data: EndpointCreate,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN, UserRole.DEVELOPER])),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new endpoint for an API version (draft-only)."""
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)
    

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
    """
    List endpoints for an API version.

    Visibility:
    - Owner org: any status
    - Other orgs: only if version is PUBLISHED
    - Platform admin: all
    """
    version = api_service.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_view_resource(auth, product.org_id, version.status)

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
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN, UserRole.DEVELOPER])),
    api_service: APIService = Depends(get_api_service),
):
    """Update an endpoint (draft-only version)."""
    endpoint = api_service.get_endpoint(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    version = api_service.get_version(endpoint.version_id)
    if not version:
        raise HTTPException(status_code=404, detail="API version not found")

    product = api_service.get_product(version.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)
   # _ensure_draft(version.status, action="update endpoints on")

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
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN, UserRole.ORG_ADMIN, UserRole.DEVELOPER])),
    api_service: APIService = Depends(get_api_service),
):
    """Create a new scope for an API product (draft-only)."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_mutate_owned_resource(auth, product.org_id)
    #_ensure_draft(product.status, action="add scopes to")

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
    """List scopes for an API product (published visible to all; draft owner-only)."""
    product = api_service.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="API product not found")

    _ensure_can_view_resource(auth, product.org_id, product.status)

    return api_service.list_scopes(product_id=product_id, limit=limit)
