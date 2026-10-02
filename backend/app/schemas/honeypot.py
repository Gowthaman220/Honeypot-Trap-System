from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class HoneypotServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    service_type: str
    port: int
    protocol: str
    status: str
    description: Optional[str] = None
    enabled: bool
    event_count: int
    last_activity: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class ServiceActionRequest(BaseModel):
    action: str  # start, stop, restart
