from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from app.schemas.event import EventResponse
from app.schemas.alert import AlertResponse


class MetricCard(BaseModel):
    label: str
    value: int
    change_percentage: Optional[float] = None
    trend: Optional[str] = None  # up, down, neutral


class ChartDataPoint(BaseModel):
    name: str
    value: int


class TimelinePoint(BaseModel):
    timestamp: str
    count: int
    high_count: int = 0


class ServiceTargetMetric(BaseModel):
    service: str
    count: int
    percentage: float


class TopSourceIP(BaseModel):
    ip: str
    count: int
    highest_severity: str
    highest_score: int
    services: List[str]


class DashboardSummary(BaseModel):
    total_events: int
    events_last_24h: int
    unique_ips: int
    high_critical_events: int
    active_services: int
    total_alerts: int
    severity_distribution: List[ChartDataPoint]
    event_type_distribution: List[ChartDataPoint]
    timeline_24h: List[TimelinePoint]
    top_services: List[ServiceTargetMetric]
    top_source_ips: List[TopSourceIP]
    recent_events: List[EventResponse]
    recent_alerts: List[AlertResponse]
