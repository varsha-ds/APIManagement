from typing import Optional, List, Dict, Any
from datetime import datetime

import logging
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.schemas.api_management import (
    APIProductCreate, APIProductUpdate, APIProductResponse,
    APIVersionCreate, APIVersionUpdate, APIVersionResponse,
    EndpointCreate, EndpointUpdate, EndpointResponse,
    ScopeCreate, ScopeResponse,
    APIStatus
)


from app.models.api_management import APIProduct, APIVersion, Endpoint, Scope  

logger = logging.getLogger(__name__)


class APIService:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _product_to_response(p: APIProduct, status: APIStatus) -> APIProductResponse:
        return APIProductResponse(
            id=str(p.id),
            org_id=str(p.org_id),
            name=p.name,
            description=p.description,
            status=status,
            is_active=p.is_active,
            created_at=p.created_at,
            updated_at=p.updated_at,
        )

    @staticmethod
    def _version_to_response(v: APIVersion) -> APIVersionResponse:
        return APIVersionResponse(
            id=str(v.id),
            product_id=str(v.product_id),
            version=v.version,
            base_path=v.base_path,
            description=v.description,
            status=v.status if isinstance(v.status, APIStatus) else APIStatus(v.status),
            created_at=v.created_at,
            updated_at=v.updated_at,
        )

    @staticmethod
    def _endpoint_to_response(e: Endpoint) -> EndpointResponse:
        scope_items = e.required_scopes or []
        scope_names = [
            s.name if hasattr(s, "name") else str(s)
            for s in scope_items
        ]
        return EndpointResponse(
            id=str(e.id),
            version_id=str(e.version_id),
            method=e.method,  
            path=e.path,
            summary=e.summary,
            description=e.description,
            required_scopes=scope_names,
            is_active=e.is_active,
            created_at=e.created_at,
            updated_at=e.updated_at,
        )

    @staticmethod
    def _scope_to_response(s: Scope) -> ScopeResponse:
        return ScopeResponse(
            id=str(s.id),
            product_id=str(s.product_id),
            name=s.name,
            description=s.description,
            created_at=s.created_at,
        )

    

    def _get_product_status(self, product_id: str) -> APIStatus:
        stmt = select(APIVersion.status).where(APIVersion.product_id == product_id)
        res = self.session.execute(stmt)
        statuses = {row[0] for row in res.all()}
        if APIStatus.PUBLISHED in statuses:
            return APIStatus.PUBLISHED
        if APIStatus.DEPRECATED in statuses:
            return APIStatus.DEPRECATED
        return APIStatus.DRAFT

    def create_product(self, org_id: str, data: APIProductCreate) -> APIProductResponse:
        p = APIProduct(
            org_id=org_id,
            name=data.name,
            description=data.description,
        )
        self.session.add(p)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            raise ValueError("API product name already exists in this organization")
        self.session.refresh(p)
        return self._product_to_response(p, APIStatus.DRAFT)

    def get_product(self, product_id: str) -> Optional[APIProductResponse]:
        res = self.session.execute(select(APIProduct).where(APIProduct.id == product_id))
        p = res.scalar_one_or_none()
        if not p:
            return None
        status = self._get_product_status(product_id)
        return self._product_to_response(p, status)

    def list_products(
        self,
        org_id: Optional[str] = None,
        is_active: Optional[bool] = None,
        status: Optional[APIStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[APIProductResponse]:
        stmt = select(APIProduct)
        if org_id:
            stmt = stmt.where(APIProduct.org_id == org_id)
        if is_active is not None:
            stmt = stmt.where(APIProduct.is_active == is_active)
        if status is not None:
            if status == APIStatus.PUBLISHED:
                published = select(APIVersion.product_id).where(APIVersion.status == APIStatus.PUBLISHED)
                stmt = stmt.where(APIProduct.id.in_(published))
            elif status == APIStatus.DEPRECATED:
                deprecated = select(APIVersion.product_id).where(APIVersion.status == APIStatus.DEPRECATED)
                stmt = stmt.where(APIProduct.id.in_(deprecated))
            else:
                non_draft = select(APIVersion.product_id).where(APIVersion.status != APIStatus.DRAFT)
                stmt = stmt.where(~APIProduct.id.in_(non_draft))

        stmt = stmt.order_by(APIProduct.created_at.desc()).offset(offset).limit(limit)
        res = self.session.execute(stmt)
        products = res.scalars().all()
        return [self._product_to_response(p, self._get_product_status(p.id)) for p in products]

    def update_product(self, product_id: str, data: APIProductUpdate) -> Optional[APIProductResponse]:
        values: Dict[str, Any] = {}
        if data.name is not None:
            values["name"] = data.name
        if data.description is not None:
            values["description"] = data.description
        if data.is_active is not None:
            values["is_active"] = data.is_active

        if not values:
            return self.get_product(product_id)

        values["updated_at"] = datetime.utcnow()

        stmt = (
            update(APIProduct)
            .where(APIProduct.id == product_id)
            .values(**values)
            .returning(APIProduct)
        )
        try:
            res = self.session.execute(stmt)
            row = res.fetchone()
            if not row:
                self.session.rollback()
                return None
            self.session.commit()
            p = row[0]
            return self._product_to_response(p, self._get_product_status(product_id))
        except IntegrityError:
            self.session.rollback()
            raise ValueError("API product name already exists in this organization")


    def create_version(self, product_id: str, data: APIVersionCreate) -> APIVersionResponse:
        if not self.get_product(product_id):
            raise ValueError("API product not found")

        v = APIVersion(
            product_id=product_id,
            version=data.version,
            base_path=data.base_path,
            description=data.description,
            status=APIStatus.DRAFT,  # default
        )
        self.session.add(v)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            raise ValueError("Version already exists for this product")
        self.session.refresh(v)
        return self._version_to_response(v)

    def get_version(self, version_id: str) -> Optional[APIVersionResponse]:
        res = self.session.execute(select(APIVersion).where(APIVersion.id == version_id))
        v = res.scalar_one_or_none()
        return self._version_to_response(v) if v else None

    def list_versions(
        self,
        product_id: str,
        status: Optional[APIStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[APIVersionResponse]:
        stmt = select(APIVersion).where(APIVersion.product_id == product_id)
        if status:
            stmt = stmt.where(APIVersion.status == status)
        stmt = stmt.order_by(APIVersion.created_at.desc()).offset(offset).limit(limit)
        res = self.session.execute(stmt)
        return [self._version_to_response(v) for v in res.scalars().all()]

    def update_version(self, version_id: str, data: APIVersionUpdate) -> Optional[APIVersionResponse]:
        values: Dict[str, Any] = {"updated_at": datetime.utcnow()}
        if data.description is not None:
            values["description"] = data.description
        if data.status is not None:
            values["status"] = data.status

        stmt = (
            update(APIVersion)
            .where(APIVersion.id == version_id)
            .values(**values)
            .returning(APIVersion)
        )
        res = self.session.execute(stmt)
        row = res.fetchone()
        if not row:
            self.session.rollback()
            return None
        self.session.commit()
        return self._version_to_response(row[0])

    def publish_version(self, version_id: str) -> Optional[APIVersionResponse]:
        return self.update_version(version_id, APIVersionUpdate(status=APIStatus.PUBLISHED))

    def deprecate_version(self, version_id: str) -> Optional[APIVersionResponse]:
        version = self.update_version(version_id, APIVersionUpdate(status=APIStatus.DEPRECATED))
        if not version:
            return None

        self.session.execute(
            update(Endpoint)
            .where(Endpoint.version_id == version_id, Endpoint.is_active == True)  
            .values(is_active=False, updated_at=datetime.utcnow())
        )
        self.session.commit()
        return version


    def create_endpoint(self, version_id: str, data: EndpointCreate) -> EndpointResponse:
        version = self.session.execute(
            select(APIVersion).where(APIVersion.id == version_id)
        ).scalar_one_or_none()
        if not version:
            raise ValueError("API version not found")

        scope_names = data.required_scopes or []
        scopes: List[Scope] = []
        if scope_names:
            res = self.session.execute(
                select(Scope).where(
                    Scope.product_id == version.product_id,
                    Scope.name.in_(scope_names),
                )
            )
            scopes = res.scalars().all()
            found = {s.name for s in scopes}
            missing = sorted(set(scope_names) - found)
            if missing:
                raise ValueError(f"Unknown scopes: {', '.join(missing)}")

        e = Endpoint(
            version_id=version_id,
            method=data.method,   
            path=data.path,
            summary=data.summary,
            description=data.description,
        )
        e.required_scopes = scopes
        self.session.add(e)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            raise ValueError("Endpoint already exists")
        self.session.refresh(e)
        return self._endpoint_to_response(e)

    def get_endpoint(self, endpoint_id: str) -> Optional[EndpointResponse]:
        res = self.session.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
        e = res.scalar_one_or_none()
        return self._endpoint_to_response(e) if e else None

    def list_endpoints(
        self,
        version_id: str,
        is_active: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EndpointResponse]:
        stmt = select(Endpoint).where(Endpoint.version_id == version_id)
        if is_active is not None:
            stmt = stmt.where(Endpoint.is_active == is_active)
        stmt = stmt.order_by(Endpoint.created_at.asc()).offset(offset).limit(limit)
        res = self.session.execute(stmt)
        return [self._endpoint_to_response(e) for e in res.scalars().all()]

    def update_endpoint(self, endpoint_id: str, data: EndpointUpdate) -> Optional[EndpointResponse]:
        e = self.session.execute(
            select(Endpoint).where(Endpoint.id == endpoint_id)
        ).scalar_one_or_none()
        if not e:
            return None

        if data.summary is not None:
            e.summary = data.summary
        if data.description is not None:
            e.description = data.description
        if data.is_active is not None:
            e.is_active = data.is_active

        if data.required_scopes is not None:
            version = self.session.execute(
                select(APIVersion).where(APIVersion.id == e.version_id)
            ).scalar_one_or_none()
            if not version:
                raise ValueError("API version not found")

            scope_names = data.required_scopes or []
            scopes: List[Scope] = []
            if scope_names:
                res = self.session.execute(
                    select(Scope).where(
                        Scope.product_id == version.product_id,
                        Scope.name.in_(scope_names),
                    )
                )
                scopes = res.scalars().all()
                found = {s.name for s in scopes}
                missing = sorted(set(scope_names) - found)
                if missing:
                    raise ValueError(f"Unknown scopes: {', '.join(missing)}")
            e.required_scopes = scopes

        e.updated_at = datetime.utcnow()
        self.session.commit()
        self.session.refresh(e)
        return self._endpoint_to_response(e)



    def create_scope(self, product_id: str, data: ScopeCreate) -> ScopeResponse:
        if not self.get_product(product_id):
            raise ValueError("API product not found")

        s = Scope(product_id=product_id, name=data.name, description=data.description)
        self.session.add(s)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            raise ValueError("Scope already exists")
        self.session.refresh(s)
        return self._scope_to_response(s)

    def list_scopes(self, product_id: str, limit: int = 100) -> List[ScopeResponse]:
        stmt = select(Scope).where(Scope.product_id == product_id).order_by(Scope.created_at.asc()).limit(limit)
        res = self.session.execute(stmt)
        return [self._scope_to_response(s) for s in res.scalars().all()]


    def generate_openapi_spec(self, version_id: str) -> dict:
        version = self.get_version(version_id)
        if not version:
            raise ValueError("API version not found")

        product = self.get_product(version.product_id)
        if not product:
            raise ValueError("API product not found")

        endpoints = self.list_endpoints(version_id, is_active=True)
        scopes = self.list_scopes(version.product_id)

        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": product.name,
                "description": product.description or "",
                "version": version.version,
            },
            "servers": [{"url": version.base_path}],
            "paths": {},
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                    "OAuth2": {
                        "type": "oauth2",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": "/api/oauth/token",
                                "scopes": {s.name: (s.description or s.name) for s in scopes},
                            }
                        },
                    },
                }
            },
        }

        for ep in endpoints:
            path = ep.path
            spec["paths"].setdefault(path, {})
            op = ep.method.value.lower() if hasattr(ep.method, "value") else str(ep.method).lower()

            spec["paths"][path][op] = {
                "summary": ep.summary,
                "description": ep.description or "",
                # OR semantics: either ApiKey or OAuth2 is accepted
                "security": [{"ApiKeyAuth": []}, {"OAuth2": ep.required_scopes}],
                "responses": {
                    "200": {"description": "Successful response"},
                    "401": {"description": "Unauthorized"},
                    "403": {"description": "Forbidden"},
                    "429": {"description": "Rate limit exceeded"},
                },
            }

        return spec
