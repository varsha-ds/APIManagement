"""
SQLAlchemy ORM models for Authentication / Users (Postgres).

- User role stored as Postgres ENUM (via Alembic)
- Password stored as password_hash only
"""

import uuid

from sqlalchemy import (Column, String, Boolean, DateTime, Enum as SAEnum, func, Index, ForeignKey,)
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


UserRoleEnum = SAEnum(
    "platform_admin",
    "org_admin",
    "developer",
    name="user_role",
    create_type=True,
)


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(320), nullable=False, unique=True, index=True)  # 320 is RFC max
    password_hash = Column(String(255), nullable=False)
    name = Column(String(200), nullable=False)
    role = Column(UserRoleEnum, nullable=False, server_default="developer")
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    is_active = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now(),
    )

    __table_args__ = (
        Index("ix_users_org_id_role", "org_id", "role"),
        Index("ix_users_is_active", "is_active"),
    )
