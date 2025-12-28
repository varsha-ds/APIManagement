from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime

    action: str

    actor_id: Optional[str] = None
    actor_type: str

    resource_type: str
    resource_id: Optional[str] = None

    decision: str
    reason: Optional[str] = None

    details: Optional[Dict[str, Any]] = None

    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
