"""
SQLAlchemy ORM models for API Management (Postgres).

Entities:
- APIProduct -> APIVersion -> Endpoint
- Scope (per product)
- Endpoint.required_scopes is Many-to-Many via endpoint_required_scopes

Designed for Alembic migrations.
"""

import uuid

from sqlalchemy import (Column, String, Boolean, DateTime, Text, ForeignKey, UniqueConstraint, Index, Enum as SAEnum, func)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


# Postgres ENUM types (created/managed via Alembic)
APIStatusEnum = SAEnum(
    "draft",
    "published",
    "deprecated",
    name="api_status",
    create_type=True,
)

HTTPMethodEnum = SAEnum(
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    name="http_method",
    create_type=True,
)


class APIProduct(Base):
    __tablename__ = "api_products"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    
    versions = relationship("APIVersion", back_populates="product", cascade="all, delete-orphan", passive_deletes=True)
    scopes = relationship("Scope", back_populates="product", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_api_products_org_id_name"),
        Index("ix_api_products_org_id_is_active", "org_id", "is_active"),
    )


class APIVersion(Base):
    __tablename__ = "api_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_id = Column(UUID(as_uuid=True), ForeignKey("api_products.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(String(20), nullable=False)      # e.g., v1, v1.0
    base_path = Column(String(255), nullable=False)   # e.g., /orders
    description = Column(Text, nullable=True)
    status = Column(APIStatusEnum, nullable=False, server_default="draft")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(),onupdate=func.now())

    product = relationship("APIProduct", back_populates="versions")
    endpoints = relationship("Endpoint", back_populates="version", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (
        UniqueConstraint("product_id", "version", name="uq_api_versions_product_id_version"),
        UniqueConstraint("product_id", "base_path", "version",name="uq_api_versions_product_id_base_path_version"),
        Index("ix_api_versions_product_id_status", "product_id", "status"),
    )


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    version_id = Column(UUID(as_uuid=True), ForeignKey("api_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    method = Column(HTTPMethodEnum, nullable=False)
    path = Column(String(255), nullable=False)   # e.g., /orders/{id}
    summary = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    
    version = relationship("APIVersion", back_populates="endpoints")
    required_scopes = relationship("Scope", secondary="endpoint_required_scopes", back_populates="endpoints", lazy="selectin")

    __table_args__ = (
        UniqueConstraint("version_id", "method", "path", name="uq_endpoints_version_id_method_path"),
        Index("ix_endpoints_version_id_is_active", "version_id", "is_active"),
    )


class Scope(Base):
    __tablename__ = "scopes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_id = Column(UUID(as_uuid=True), ForeignKey("api_products.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)   # e.g., orders.read
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    product = relationship("APIProduct", back_populates="scopes")
    endpoints = relationship("Endpoint", secondary="endpoint_required_scopes", back_populates="required_scopes")

    __table_args__ = (
        UniqueConstraint("product_id", "name", name="uq_scopes_product_id_name"),
        Index("ix_scopes_product_id_name", "product_id", "name"),
    )


class EndpointRequiredScope(Base):
    """
    Association table for Endpoint <-> Scope (required scopes).
    Composite PK prevents duplicates.
    """

    __tablename__ = "endpoint_required_scopes"

    endpoint_id = Column(UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="CASCADE"), primary_key=True)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True)

    __table_args__ = (
        Index("ix_endpoint_required_scopes_endpoint_id", "endpoint_id"),
        Index("ix_endpoint_required_scopes_scope_id", "scope_id"),
    )
