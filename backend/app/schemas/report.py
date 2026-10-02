from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from app.schemas.dashboard import ChartDataPoint, ServiceTargetMetric, TopSourceIP


class ReportSummary(BaseModel):
    generated_at: datetime
    report_period: str  # "daily", "weekly", "custom"
    start_date: datetime
    end_date: datetime
    total_events: int
    unique_sources: int
    total_alerts: int
    severity_breakdown: List[ChartDataPoint]
    top_targeted_services: List[ServiceTargetMetric]
    top_threat_sources: List[TopSourceIP]
    triggered_rules: List[ChartDataPoint]
    executive_summary: str
