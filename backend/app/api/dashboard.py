from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.core.database import get_db
from app.models.event import Event
from app.models.honeypot_service import HoneypotService
from app.models.alert import Alert
from app.models.ip_stat import IPStatistic
from app.schemas.dashboard import DashboardSummary, ChartDataPoint, TimelinePoint, ServiceTargetMetric, TopSourceIP
from app.schemas.event import EventResponse
from app.schemas.alert import AlertResponse
from app.api.deps import get_current_user
import json

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """Computes and returns aggregated SOC-style dashboard statistics."""
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    # 1. Total events
    total_events = db.query(func.count(Event.id)).scalar() or 0

    # 2. Events last 24 hours
    events_last_24h = db.query(func.count(Event.id)).filter(Event.timestamp >= last_24h).scalar() or 0

    # 3. Unique IPs
    unique_ips = db.query(func.count(func.distinct(Event.source_ip))).scalar() or 0

    # 4. High / Critical events
    high_critical = db.query(func.count(Event.id)).filter(
        Event.severity.in_(["HIGH", "CRITICAL"])
    ).scalar() or 0

    # 5. Active honeypot services
    active_services = db.query(func.count(HoneypotService.id)).filter(
        HoneypotService.status == "running"
    ).scalar() or 0

    # 6. Total alerts
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "NEW").scalar() or 0

    # 7. Severity distribution
    sev_rows = db.query(Event.severity, func.count(Event.id)).group_by(Event.severity).all()
    severity_distribution = [
        ChartDataPoint(name=row[0] or "UNKNOWN", value=row[1]) for row in sev_rows
    ]

    # Ensure all 4 severities are represented
    existing_sevs = {p.name for p in severity_distribution}
    for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        if s not in existing_sevs:
            severity_distribution.append(ChartDataPoint(name=s, value=0))

    # 8. Event type distribution
    type_rows = db.query(Event.event_type, func.count(Event.id)).group_by(Event.event_type).all()
    event_type_distribution = [
        ChartDataPoint(name=row[0] or "UNKNOWN", value=row[1]) for row in type_rows
    ]

    # 9. 24-hour timeline breakdown (binned into 6 4-hour slots or hourly)
    timeline_24h = []
    for i in range(6, -1, -1):
        slot_start = now - timedelta(hours=(i + 1) * 4)
        slot_end = now - timedelta(hours=i * 4)
        count = db.query(func.count(Event.id)).filter(
            Event.timestamp >= slot_start, Event.timestamp < slot_end
        ).scalar() or 0
        high_cnt = db.query(func.count(Event.id)).filter(
            Event.timestamp >= slot_start, Event.timestamp < slot_end,
            Event.severity.in_(["HIGH", "CRITICAL"])
        ).scalar() or 0
        label = slot_end.strftime("%H:%M")
        timeline_24h.append(TimelinePoint(timestamp=label, count=count, high_count=high_cnt))

    # 10. Top targeted services
    svc_rows = db.query(Event.service, func.count(Event.id)).group_by(Event.service).order_by(desc(func.count(Event.id))).limit(5).all()
    top_services = []
    for s_name, count in svc_rows:
        pct = round((count / total_events * 100), 1) if total_events > 0 else 0.0
        top_services.append(ServiceTargetMetric(service=s_name or "Unknown", count=count, percentage=pct))

    # 11. Top source IPs
    ip_rows = db.query(
        Event.source_ip,
        func.count(Event.id).label("cnt"),
        func.max(Event.risk_score).label("max_score")
    ).group_by(Event.source_ip).order_by(desc("cnt")).limit(5).all()

    top_source_ips = []
    for ip, cnt, max_score in ip_rows:
        # Determine highest severity for this IP
        top_sev = db.query(Event.severity).filter(Event.source_ip == ip).order_by(desc(Event.risk_score)).first()
        sev_str = top_sev[0] if top_sev else "LOW"
        # Find distinct services targeted
        services = [s[0] for s in db.query(Event.service).filter(Event.source_ip == ip).distinct().all() if s[0]]
        top_source_ips.append(TopSourceIP(
            ip=ip,
            count=cnt,
            highest_severity=sev_str,
            highest_score=max_score or 0,
            services=services
        ))

    # 12. Recent events (latest 8)
    recent_events = db.query(Event).order_by(desc(Event.timestamp)).limit(8).all()

    # 13. Recent alerts (latest 5)
    recent_alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(5).all()

    return DashboardSummary(
        total_events=total_events,
        events_last_24h=events_last_24h,
        unique_ips=unique_ips,
        high_critical_events=high_critical,
        active_services=active_services,
        total_alerts=total_alerts,
        severity_distribution=severity_distribution,
        event_type_distribution=event_type_distribution,
        timeline_24h=timeline_24h,
        top_services=top_services,
        top_source_ips=top_source_ips,
        recent_events=recent_events,
        recent_alerts=recent_alerts
    )
