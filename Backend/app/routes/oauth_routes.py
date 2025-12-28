
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Request, Form
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.key_service import KeyService
from app.services.subscription_service import SubscriptionService
from app.middleware.audit_log import audit_log
from app.middleware.rate_limiter import rate_limit_check

from app.utils.security import (
    create_oauth_token,
    OAUTH_TOKEN_EXPIRE_SECONDS,
    decode_token,
    verify_client_secret, 
)
from app.schemas.oauth import OAuthTokenResponse

router = APIRouter(prefix="/oauth", tags=["OAuth2"])


def get_key_service(db: Session = Depends(get_db)) -> KeyService:
    return KeyService(db)


def get_subscription_service(db: Session = Depends(get_db)) -> SubscriptionService:
    return SubscriptionService(db)


@router.post("/token", response_model=OAuthTokenResponse)
def token_endpoint(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(...),          # OAuth public client_id
    client_secret: str = Form(...),      # OAuth secret
    scope: Optional[str] = Form(None),   # space-separated
    key_service: KeyService = Depends(get_key_service),
    sub_service: SubscriptionService = Depends(get_subscription_service),
):

    # Rate limit token requests per client_id
    rate_limit_check(f"oauth:token:{client_id}")

    # Validate grant type
    if grant_type != "client_credentials":
        audit_log(
            action="oauth.token",
            actor_id=client_id,
            actor_type="app_client",
            resource_type="oauth",
            decision="denied",
            reason="invalid_grant_type",
            request=request,
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_grant_type",
                "error_description": "Only 'client_credentials' grant type is supported",
            },
        )

    # Find client by OAuth client_id (public id)
    client = key_service.get_app_client_by_oauth_id(client_id)
    if not client:
        audit_log(
            action="oauth.token",
            actor_id=client_id,
            actor_type="app_client",
            resource_type="oauth",
            decision="denied",
            reason="client_not_found",
            request=request,
        )
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "Client not found"},
        )

    if not client.is_active:
        audit_log(
            action="oauth.token",
            actor_id=client_id,
            actor_type="app_client",
            resource_type="oauth",
            decision="denied",
            reason="client_inactive",
            request=request,
        )
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "Client is inactive"},
        )

    # Verify client secret (recommended: password-hash verification, not deterministic hashing)
    if not verify_client_secret(client_secret, client.client_secret_hash):
        audit_log(
            action="oauth.token",
            actor_id=client_id,
            actor_type="app_client",
            resource_type="oauth",
            decision="denied",
            reason="invalid_secret",
            request=request,
        )
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "Invalid client credentials"},
        )


    granted_scopes: List[str] = sub_service.get_client_scopes(client.id)

    if not granted_scopes:
        audit_log(
            action="oauth.token",
            actor_id=client_id,
            actor_type="app_client",
            resource_type="oauth",
            decision="denied",
            reason="no_approved_subscriptions",
            request=request,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "access_denied",
                "error_description": "No approved subscriptions. Request API access first.",
            },
        )

  
    token_scopes = granted_scopes
    if scope:
        requested_scopes = scope.split()
        invalid = set(requested_scopes) - set(granted_scopes)
        if invalid:
            audit_log(
                action="oauth.token",
                actor_id=client_id,
                actor_type="app_client",
                resource_type="oauth",
                decision="denied",
                reason="invalid_scopes",
                details={"invalid": list(invalid), "granted": granted_scopes},
                request=request,
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_scope",
                    "error_description": f"Requested scopes not granted: {sorted(list(invalid))}",
                },
            )
        token_scopes = requested_scopes

    access_token = create_oauth_token(
        client_id=client_id,             
        scopes=token_scopes,
        expires_in=OAUTH_TOKEN_EXPIRE_SECONDS,
    )

    audit_log(
        action="oauth.token",
        actor_id=client_id,
        actor_type="app_client",
        resource_type="oauth",
        details={"scopes": token_scopes},
        request=request,
    )

    return OAuthTokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=OAUTH_TOKEN_EXPIRE_SECONDS,
        scope=" ".join(token_scopes) if token_scopes else None,
    )


@router.post("/introspect")
def introspect_token(
    request: Request,
    token: str = Form(...),
):

    payload = decode_token(token)
    if not payload:
        return {"active": False}

    scopes = payload.get("scopes", []) or []
    exp = payload.get("exp")
    iat = payload.get("iat")

   
    def _to_int_ts(x):
        if x is None:
            return None
        if isinstance(x, int):
            return x
        return int(x.timestamp())

    return {
        "active": True,
        "client_id": payload.get("sub"),
        "scope": " ".join(scopes),
        "token_type": "bearer",
        "exp": _to_int_ts(exp),
        "iat": _to_int_ts(iat),
    }
