from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict
from app.schemas.detection import DetectionResponse


class RawEventInput(BaseModel):
    source_ip: str
    source_port: Optional[int] = None
    destination_port: int
    protocol: str = "TCP"
    service: str
    event_type: str = "CONNECTION"
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    raw_payload: Optional[str] = None


class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: str
    timestamp: datetime
    source_ip: str
    source_port: Optional[int] = None
    destination_port: int
    protocol: str
    service: str
    event_type: str
    severity: str
    risk_score: int
    session_id: Optional[str] = None
    metadata_json: Optional[str] = None
    raw_payload: Optional[str] = None
    created_at: datetime


class EventDetailResponse(EventResponse):
    detections: List[DetectionResponse] = []


class PaginatedEventsResponse(BaseModel):
    items: List[EventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
