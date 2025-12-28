"""Audit log ORM model (Postgres + SQLAlchemy)."""

from uuid import uuid4

from sqlalchemy import Column, DateTime, String, Text, Index, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    action = Column(String(255), nullable=False, index=True)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_type = Column(String(50), nullable=False)  # user/app_client/system/anonymous
    resource_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(255), nullable=True)
    decision = Column(String(20), nullable=False, index=True)  # allowed/denied
    reason = Column(Text, nullable=True)
    details = Column(JSONB, nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    request_id = Column(String(128), nullable=True, index=True)


Index("ix_audit_logs_actor_action_ts", AuditLog.actor_id, AuditLog.action, AuditLog.timestamp)
