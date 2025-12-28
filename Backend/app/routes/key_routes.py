from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from app.database import get_db

from app.schemas.app_client import (
    AppClientCreate, AppClientUpdate, AppClientResponse, AppClientWithSecret,
    APIKeyCreate, APIKeyResponse, APIKeyCreated, RotateSecretResponse,
)
from app.schemas.auth import UserRole
from app.services.key_service import KeyService
from app.middleware.auth_middleware import get_current_user, AuthContext, RoleChecker
from app.middleware.audit_log import audit_log

router = APIRouter(prefix="/clients", tags=["App Clients & API Keys"])


def get_key_service(db: Session = Depends(get_db)) -> KeyService:
    return KeyService(db)



@router.post("", response_model=AppClientWithSecret)
def create_app_client(
    data: AppClientCreate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):

    if not auth.org_id and auth.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(status_code=400, detail="User must belong to an organization to create app clients")

    # Determine org_id: non-platform users always in their org.
    org_id = auth.org_id
    if auth.role == UserRole.PLATFORM_ADMIN:
        # If your schema includes org_id, you can allow platform admin to specify it.
        org_id = getattr(data, "org_id", None) or auth.org_id

    if not org_id:
        raise HTTPException(status_code=400, detail="org_id is required to create app clients")

    try:
        client = key_service.create_app_client(org_id=org_id, data=data)

        audit_log(
            action="client.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="app_client",
            resource_id=str(client.id),
            request=request,
        )
        return client
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=List[AppClientResponse])
def list_app_clients(
    is_active: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):
    
    if auth.role == UserRole.PLATFORM_ADMIN:
        return key_service.list_app_clients_admin(is_active=is_active, limit=limit, offset=offset)

    if not auth.org_id:
        return []

    return key_service.list_app_clients(
        org_id=auth.org_id,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )



@router.get("/admin/keys", response_model=List[APIKeyResponse])
def admin_list_all_keys(
    org_id: Optional[UUID] = None,
    is_active: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    key_service: KeyService = Depends(get_key_service),
):
    return key_service.list_all_keys_admin(
        org_id=org_id,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )


@router.delete("/admin/keys/{key_id}")
def admin_revoke_key(
    key_id: UUID,
    request: Request,
    auth: AuthContext = Depends(RoleChecker([UserRole.PLATFORM_ADMIN])),
    key_service: KeyService = Depends(get_key_service),
):
    
    success = key_service.revoke_api_key(key_id, revoked_by=auth.identity_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")

    audit_log(
        action="admin.key.revoke",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="api_key",
        resource_id=str(key_id),
        request=request,
    )
    return {"message": "API key revoked by admin"}




@router.post("/{client_id}/keys", response_model=APIKeyCreated)
def create_api_key(
    client_id: UUID,
    data: APIKeyCreate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):
   
    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        created = key_service.create_api_key(client_id, data)

        audit_log(
            action="key.create",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="api_key",
            resource_id=str(created.id),
            details={"client_id": str(client_id), "prefix": created.prefix},
            request=request,
        )
        return created
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{client_id}/keys", response_model=List[APIKeyResponse])
def list_api_keys(
    client_id: UUID,
    is_active: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):
    
    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return key_service.list_api_keys(
        app_client_id=client_id,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )


@router.post("/{client_id}/keys/{key_id}/rotate", response_model=APIKeyCreated)
def rotate_api_key(
    client_id: UUID,
    key_id: UUID,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):

    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        new_key = key_service.rotate_api_key(key_id, revoked_by=auth.identity_id)

        audit_log(
            action="key.rotate",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="api_key",
            resource_id=str(key_id),
            details={"new_key_id": str(new_key.id), "new_prefix": new_key.prefix},
            request=request,
        )
        return new_key
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{client_id}/keys/{key_id}")
def revoke_api_key(
    client_id: UUID,
    key_id: UUID,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):
    
    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    success = key_service.revoke_api_key(key_id, revoked_by=auth.identity_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")

    audit_log(
        action="key.revoke",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="api_key",
        resource_id=str(key_id),
        request=request,
    )
    return {"message": "API key revoked"}


@router.get("/{client_id}", response_model=AppClientResponse)
def get_app_client(
    client_id: UUID,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):
   
    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return client


@router.patch("/{client_id}", response_model=AppClientResponse)
def update_app_client(
    client_id: UUID,
    data: AppClientUpdate,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):
    
    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    updated = key_service.update_app_client(client_id, data)

    audit_log(
        action="client.update",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="app_client",
        resource_id=str(client_id),
        request=request,
    )
    return updated


@router.post("/{client_id}/rotate-secret", response_model=RotateSecretResponse)
def rotate_client_secret(
    client_id: UUID,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):

    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        oauth_client_id, new_secret = key_service.rotate_client_secret(client_id)

        audit_log(
            action="client.rotate_secret",
            actor_id=str(auth.identity_id),
            actor_type="user",
            resource_type="app_client",
            resource_id=str(client_id),
            request=request,
        )

        return {
            "client_id": oauth_client_id,
            "client_secret": new_secret,
            "message": "Secret rotated. Store this new secret securely - it cannot be retrieved again.",
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{client_id}")
def deactivate_app_client(
    client_id: UUID,
    request: Request,
    auth: AuthContext = Depends(get_current_user),
    key_service: KeyService = Depends(get_key_service),
):
   
    client = key_service.get_app_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="App client not found")

    if auth.role != UserRole.PLATFORM_ADMIN and auth.org_id != client.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    key_service.deactivate_app_client(client_id)

    audit_log(
        action="client.deactivate",
        actor_id=str(auth.identity_id),
        actor_type="user",
        resource_type="app_client",
        resource_id=str(client_id),
        request=request,
    )

    return {"message": "App client and all API keys deactivated"}
