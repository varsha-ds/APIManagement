"""
SQLAlchemy ORM model for Organizations (Postgres).
"""

import uuid

from sqlalchemy import (Column, String, Boolean, DateTime, Text, func, Index, UniqueConstraint,)
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("name", name="uq_organizations_name"),
        Index("ix_organizations_is_active", "is_active"),
    )
