"""Audit logging middleware (Postgres + SQLAlchemy sync)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import logging
import json
from uuid import uuid4

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

REDACT_KEYS = {
    "password", "pass", "secret", "token",
    "access_token", "refresh_token",
    "authorization", "api_key", "apikey",
    "client_secret",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except Exception:
        return str(value)


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in REDACT_KEYS:
                out[k] = "***REDACTED***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


class AuditLogger:
    """
    Audit logger that writes to:
    - application logs (INFO/WARN)
    - Postgres table `audit_logs`
    """

    def __init__(self):
        self._session_factory = None  # set via set_session_factory()

    def set_session_factory(self, session_factory):
        """
        session_factory should be something like SessionLocal from app.database
        """
        self._session_factory = session_factory

    def log(
        self,
        action: str,
        actor_id: str,
        actor_type: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        decision: str = "allowed",
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        event_id = uuid4()
        ts = _utc_now()
        safe_details = _safe_json(_redact(details or {}))

        # app log line
        log_level = logging.WARNING if decision == "denied" else logging.INFO
        logger.log(
            log_level,
            "AUDIT action=%s actor=%s:%s resource=%s:%s decision=%s request_id=%s reason=%s",
            action, actor_type, actor_id, resource_type, resource_id, decision, request_id, reason
        )

        # persist to db
        close_after = False
        if db is None:
            if self._session_factory is None:
                # still return event even if DB not configured
                return {
                    "id": str(event_id),
                    "timestamp": ts.isoformat(),
                    "action": action,
                    "actor_id": actor_id,
                    "actor_type": actor_type,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "decision": decision,
                    "reason": reason,
                    "details": safe_details,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "request_id": request_id,
                }
            db = self._session_factory()
            close_after = True

        try:
            row = AuditLog(
                id=event_id,
                timestamp=ts,
                action=action,
                actor_id=actor_id,
                actor_type=actor_type,
                resource_type=resource_type,
                resource_id=resource_id,
                decision=decision,
                reason=reason,
                details=safe_details,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            db.add(row)
            db.commit()
        except Exception:
            logger.exception("Failed to store audit log")
            try:
                db.rollback()
            except Exception:
                logger.exception("Failed rollback after audit log failure")
        finally:
            if close_after:
                db.close()

        return {
            "id": str(event_id),
            "timestamp": ts.isoformat(),
            "action": action,
            "actor_id": actor_id,
            "actor_type": actor_type,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "decision": decision,
            "reason": reason,
            "details": safe_details,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_id": request_id,
        }

    def get_logs(
        self,
        db: Session,
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        action: Optional[str] = None,
        decision: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        q = db.query(AuditLog)

        if actor_id:
            q = q.filter(AuditLog.actor_id == actor_id)
        if resource_type:
            q = q.filter(AuditLog.resource_type == resource_type)
        if action:
            q = q.filter(AuditLog.action.ilike(f"%{action}%"))
        if decision:
            q = q.filter(AuditLog.decision == decision)

        return q.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()


audit_logger = AuditLogger()


def audit_log(
    action: str,
    actor_id: str,
    actor_type: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    decision: str = "allowed",
    reason: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    request=None,
    db: Optional[Session] = None,
):
    ip_address = None
    user_agent = None
    request_id = None

    if request:
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        request_id = getattr(request.state, "request_id", None)

    return audit_logger.log(
        action=action,
        actor_id=str(actor_id),
        actor_type=actor_type,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        decision=decision,
        reason=reason,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        db=db,
    )
