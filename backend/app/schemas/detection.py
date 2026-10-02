from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class DetectionBase(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    severity: str
    score: int
    evidence: Optional[str] = None
    event_id: str
    source_ip: str


class DetectionCreate(DetectionBase):
    pass


class DetectionResponse(DetectionBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detection_timestamp: datetime
