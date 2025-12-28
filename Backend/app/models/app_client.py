"""
SQLAlchemy ORM models for App Clients + API Keys (Postgres).

- AppClient: stores OAuth-like client_id and hashed client_secret
- APIKey: stores prefix + hashed key, plus usage and revocation metadata

Notes:
- client_secret_hash and key_hash store hashes (never store raw secrets)
- prefix is used for identification (first N chars of the issued key)
"""

import uuid

from sqlalchemy import (Column, String, Boolean, DateTime, Text, ForeignKey, UniqueConstraint, Index, func)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class AppClient(Base):
    __tablename__ = "app_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True),ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    client_id = Column(UUID(as_uuid=True), nullable=False, default=uuid.uuid4, unique=True, index=True)# OAuth-like identifier used publicly
    client_secret_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    api_keys = relationship("APIKey", back_populates="app_client", cascade="all, delete-orphan", passive_deletes=True)
    subscriptions = relationship("Subscription", back_populates="app_client", cascade="all, delete-orphan", passive_deletes=True)
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_app_clients_org_id_name"),
        Index("ix_app_clients_org_id_is_active", "org_id", "is_active"),
    )

    


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    app_client_id = Column(UUID(as_uuid=True), ForeignKey("app_clients.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    prefix = Column(String(32), nullable=False, index=True)
    key_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, server_default="true")
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True) 

    app_client = relationship("AppClient", back_populates="api_keys")

    __table_args__ = (
        UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
        UniqueConstraint("app_client_id", "name", name="uq_api_keys_app_client_id_name"),
        UniqueConstraint("prefix", name="uq_api_keys_prefix"),
        Index("ix_api_keys_app_client_id_is_active", "app_client_id", "is_active"),
    )

