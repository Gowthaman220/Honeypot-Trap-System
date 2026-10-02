from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AlertBase(BaseModel):
    title: str
    severity: str
    source_ip: str
    detection_id: Optional[int] = None
    event_id: Optional[str] = None
    notes: Optional[str] = None


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    status: Optional[str] = None  # NEW, ACKNOWLEDGED, RESOLVED
    notes: Optional[str] = None


class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    timestamp: datetime
    status: str
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
