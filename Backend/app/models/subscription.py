"""
SQLAlchemy ORM models for Subscriptions (Postgres).

A subscription links:
- AppClient -> APIVersion
and tracks status, justification, approvals, rate limit, and requested/granted scopes.

Scopes are normalized:
- requested_scopes: many-to-many via subscription_requested_scopes
- granted_scopes: many-to-many via subscription_granted_scopes
"""

import uuid

from sqlalchemy import (Column, Integer, String, DateTime, Text, ForeignKey, UniqueConstraint, Index, Enum as SAEnum, func)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


SubscriptionStatusEnum = SAEnum(
    "pending",
    "approved",
    "denied",
    "revoked",
    name="subscription_status",
    create_type=True,
)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    app_client_id = Column(UUID(as_uuid=True), ForeignKey("app_clients.id", ondelete="CASCADE"), nullable=False, index=True)
    api_version_id = Column(UUID(as_uuid=True), ForeignKey("api_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(SubscriptionStatusEnum, nullable=False, server_default="pending")
    rate_limit_per_minute = Column(Integer, nullable=False, server_default="100")
    justification = Column(Text, nullable=True)
    denial_reason = Column(Text, nullable=True)
    # Approver is a user (nullable because pending/denied may not have it)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    # Relationships (optional but useful)
    app_client = relationship("AppClient", back_populates="subscriptions", lazy="selectin")
    api_version = relationship("APIVersion", lazy="selectin")
    approver = relationship("User", lazy="selectin")
    requested_scopes = relationship("Scope", secondary="subscription_requested_scopes", lazy="selectin")
    granted_scopes = relationship("Scope", secondary="subscription_granted_scopes", lazy="selectin")

    __table_args__ = (
        # One subscription per (client, api_version). Approvals update this row instead of creating another.
        UniqueConstraint("app_client_id", "api_version_id", name="uq_subscriptions_app_client_api_version"),
        Index("ix_subscriptions_status", "status"),
        Index("ix_subscriptions_app_client_id_status", "app_client_id", "status"),
        Index("ix_subscriptions_api_version_id_status", "api_version_id", "status"),
    )


class SubscriptionRequestedScope(Base):
    __tablename__ = "subscription_requested_scopes"

    subscription_id = Column(UUID(as_uuid=True), ForeignKey("subscriptions.id", ondelete="CASCADE"), primary_key=True,)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True)

    __table_args__ = (
        Index("ix_sub_req_scopes_subscription_id", "subscription_id"),
        Index("ix_sub_req_scopes_scope_id", "scope_id"),
    )


class SubscriptionGrantedScope(Base):
    __tablename__ = "subscription_granted_scopes"

    subscription_id = Column(UUID(as_uuid=True), ForeignKey("subscriptions.id", ondelete="CASCADE"), primary_key=True)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True)

    __table_args__ = (
        Index("ix_sub_grant_scopes_subscription_id", "subscription_id"),
        Index("ix_sub_grant_scopes_scope_id", "scope_id"),
    )
