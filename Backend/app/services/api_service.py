"""API Management service (Postgres/SQLAlchemy)."""
from __future__ import annotations

from typing import Optional, List, Dict, Any
from datetime import datetime

import logging
from sqlalchemy import select, update, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.api_management import (
    APIProductCreate, APIProductUpdate, APIProductResponse,
    APIVersionCreate, APIVersionUpdate, APIVersionResponse,
    EndpointCreate, EndpointUpdate, EndpointResponse,
    ScopeCreate, ScopeResponse,
    APIStatus
)

# TODO: replace these with your actual SQLAlchemy ORM models
from app.models.api_management import APIProduct, APIVersion, Endpoint, Scope  # <- adjust

logger = logging.getLogger(__name__)


class APIService:
    def __init__(self, session: AsyncSession):
        self.session = session

    # ------------------ helpers ------------------

    @staticmethod
    def _product_to_response(p: APIProduct) -> APIProductResponse:
        return APIProductResponse(
            id=str(p.id),
            org_id=str(p.org_id),
            name=p.name,
            description=p.description,
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
        return EndpointResponse(
            id=str(e.id),
            version_id=str(e.version_id),
            method=e.method,  # prefer storing as enum in DB
            path=e.path,
            summary=e.summary,
            description=e.description,
            required_scopes=e.required_scopes or [],
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

    # ================== API Products ==================

    async def create_product(self, org_id: str, data: APIProductCreate) -> APIProductResponse:
        p = APIProduct(
            org_id=org_id,
            name=data.name,
            description=data.description,
        )
        self.session.add(p)
        try:
            await self.session.commit()
        except IntegrityError:
            await self.session.rollback()
            # assumes unique (org_id, name)
            raise ValueError("API product name already exists in this organization")
        await self.session.refresh(p)
        return self._product_to_response(p)

    async def get_product(self, product_id: str) -> Optional[APIProductResponse]:
        res = await self.session.execute(select(APIProduct).where(APIProduct.id == product_id))
        p = res.scalar_one_or_none()
        return self._product_to_response(p) if p else None

    async def list_products(
        self,
        org_id: Optional[str] = None,
        is_active: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[APIProductResponse]:
        stmt = select(APIProduct)
        if org_id:
            stmt = stmt.where(APIProduct.org_id == org_id)
        if is_active is not None:
            stmt = stmt.where(APIProduct.is_active == is_active)

        stmt = stmt.order_by(APIProduct.created_at.desc()).offset(offset).limit(limit)
        res = await self.session.execute(stmt)
        return [self._product_to_response(p) for p in res.scalars().all()]

    async def update_product(self, product_id: str, data: APIProductUpdate) -> Optional[APIProductResponse]:
        values: Dict[str, Any] = {}
        if data.name is not None:
            values["name"] = data.name
        if data.description is not None:
            values["description"] = data.description
        if data.is_active is not None:
            values["is_active"] = data.is_active

        if not values:
            return await self.get_product(product_id)

        values["updated_at"] = datetime.utcnow()

        stmt = (
            update(APIProduct)
            .where(APIProduct.id == product_id)
            .values(**values)
            .returning(APIProduct)
        )
        try:
            res = await self.session.execute(stmt)
            row = res.fetchone()
            if not row:
                await self.session.rollback()
                return None
            await self.session.commit()
            p = row[0]
            return self._product_to_response(p)
        except IntegrityError:
            await self.session.rollback()
            raise ValueError("API product name already exists in this organization")

    # ================== API Versions ==================

    async def create_version(self, product_id: str, data: APIVersionCreate) -> APIVersionResponse:
        # Ensure product exists
        if not await self.get_product(product_id):
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
            await self.session.commit()
        except IntegrityError:
            await self.session.rollback()
            # assumes unique (product_id, version)
            raise ValueError("Version already exists for this product")
        await self.session.refresh(v)
        return self._version_to_response(v)

    async def get_version(self, version_id: str) -> Optional[APIVersionResponse]:
        res = await self.session.execute(select(APIVersion).where(APIVersion.id == version_id))
        v = res.scalar_one_or_none()
        return self._version_to_response(v) if v else None

    async def list_versions(
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
        res = await self.session.execute(stmt)
        return [self._version_to_response(v) for v in res.scalars().all()]

    async def update_version(self, version_id: str, data: APIVersionUpdate) -> Optional[APIVersionResponse]:
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
        res = await self.session.execute(stmt)
        row = res.fetchone()
        if not row:
            await self.session.rollback()
            return None
        await self.session.commit()
        return self._version_to_response(row[0])

    async def publish_version(self, version_id: str) -> Optional[APIVersionResponse]:
        return await self.update_version(version_id, APIVersionUpdate(status=APIStatus.PUBLISHED))

    async def deprecate_version(self, version_id: str) -> Optional[APIVersionResponse]:
        return await self.update_version(version_id, APIVersionUpdate(status=APIStatus.DEPRECATED))

    # ================== Endpoints ==================

    async def create_endpoint(self, version_id: str, data: EndpointCreate) -> EndpointResponse:
        if not await self.get_version(version_id):
            raise ValueError("API version not found")

        e = Endpoint(
            version_id=version_id,
            method=data.method,   # store enum
            path=data.path,
            summary=data.summary,
            description=data.description,
            required_scopes=data.required_scopes or [],
        )
        self.session.add(e)
        try:
            await self.session.commit()
        except IntegrityError:
            await self.session.rollback()
            # assumes unique (version_id, method, path)
            raise ValueError("Endpoint already exists")
        await self.session.refresh(e)
        return self._endpoint_to_response(e)

    async def get_endpoint(self, endpoint_id: str) -> Optional[EndpointResponse]:
        res = await self.session.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
        e = res.scalar_one_or_none()
        return self._endpoint_to_response(e) if e else None

    async def list_endpoints(
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
        res = await self.session.execute(stmt)
        return [self._endpoint_to_response(e) for e in res.scalars().all()]

    async def update_endpoint(self, endpoint_id: str, data: EndpointUpdate) -> Optional[EndpointResponse]:
        values: Dict[str, Any] = {"updated_at": datetime.utcnow()}
        if data.summary is not None:
            values["summary"] = data.summary
        if data.description is not None:
            values["description"] = data.description
        if data.required_scopes is not None:
            values["required_scopes"] = data.required_scopes
        if data.is_active is not None:
            values["is_active"] = data.is_active

        stmt = (
            update(Endpoint)
            .where(Endpoint.id == endpoint_id)
            .values(**values)
            .returning(Endpoint)
        )
        res = await self.session.execute(stmt)
        row = res.fetchone()
        if not row:
            await self.session.rollback()
            return None
        await self.session.commit()
        return self._endpoint_to_response(row[0])

    # ================== Scopes ==================

    async def create_scope(self, product_id: str, data: ScopeCreate) -> ScopeResponse:
        if not await self.get_product(product_id):
            raise ValueError("API product not found")

        s = Scope(product_id=product_id, name=data.name, description=data.description)
        self.session.add(s)
        try:
            await self.session.commit()
        except IntegrityError:
            await self.session.rollback()
            raise ValueError("Scope already exists")
        await self.session.refresh(s)
        return self._scope_to_response(s)

    async def list_scopes(self, product_id: str, limit: int = 100) -> List[ScopeResponse]:
        stmt = select(Scope).where(Scope.product_id == product_id).order_by(Scope.created_at.asc()).limit(limit)
        res = await self.session.execute(stmt)
        return [self._scope_to_response(s) for s in res.scalars().all()]

    # ================== OpenAPI Generation ==================

    async def generate_openapi_spec(self, version_id: str) -> dict:
        version = await self.get_version(version_id)
        if not version:
            raise ValueError("API version not found")

        product = await self.get_product(version.product_id)
        if not product:
            raise ValueError("API product not found")

        endpoints = await self.list_endpoints(version_id, is_active=True)
        scopes = await self.list_scopes(version.product_id)

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
