import io
import csv
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.core.database import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.models.detection import Detection
from app.schemas.report import ReportSummary
from app.schemas.dashboard import ChartDataPoint, ServiceTargetMetric, TopSourceIP
from app.api.deps import get_current_user

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/summary", response_model=ReportSummary)
def get_report_summary(
    period: str = Query("daily", pattern="^(daily|weekly|custom)$"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Generates an academic-grade threat intelligence report for the selected timeframe."""
    now = datetime.now(timezone.utc)
    if period == "daily":
        start = now - timedelta(days=1)
        end = now
    elif period == "weekly":
        start = now - timedelta(days=7)
        end = now
    else:
        start = datetime.fromisoformat(start_date) if start_date else now - timedelta(days=30)
        end = datetime.fromisoformat(end_date) if end_date else now

    # Metrics in range
    total_events = db.query(func.count(Event.id)).filter(Event.timestamp >= start, Event.timestamp <= end).scalar() or 0
    unique_sources = db.query(func.count(func.distinct(Event.source_ip))).filter(Event.timestamp >= start, Event.timestamp <= end).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.timestamp >= start, Alert.timestamp <= end).scalar() or 0

    # Severity breakdown
    sev_rows = db.query(Event.severity, func.count(Event.id)).filter(
        Event.timestamp >= start, Event.timestamp <= end
    ).group_by(Event.severity).all()
    severity_breakdown = [ChartDataPoint(name=r[0] or "UNKNOWN", value=r[1]) for r in sev_rows]

    # Top targeted services
    svc_rows = db.query(Event.service, func.count(Event.id)).filter(
        Event.timestamp >= start, Event.timestamp <= end
    ).group_by(Event.service).order_by(desc(func.count(Event.id))).limit(5).all()

    top_targeted_services = []
    for s_name, count in svc_rows:
        pct = round((count / total_events * 100), 1) if total_events > 0 else 0.0
        top_targeted_services.append(ServiceTargetMetric(service=s_name, count=count, percentage=pct))

    # Top threat sources
    ip_rows = db.query(
        Event.source_ip,
        func.count(Event.id).label("cnt"),
        func.max(Event.risk_score).label("max_score")
    ).filter(Event.timestamp >= start, Event.timestamp <= end).group_by(Event.source_ip).order_by(desc("cnt")).limit(5).all()

    top_threat_sources = []
    for ip, cnt, max_score in ip_rows:
        top_sev = db.query(Event.severity).filter(Event.source_ip == ip).order_by(desc(Event.risk_score)).first()
        services = [s[0] for s in db.query(Event.service).filter(Event.source_ip == ip).distinct().all() if s[0]]
        top_threat_sources.append(TopSourceIP(
            ip=ip, count=cnt, highest_severity=top_sev[0] if top_sev else "LOW",
            highest_score=max_score or 0, services=services
        ))

    # Triggered rules
    rule_rows = db.query(Detection.rule_name, func.count(Detection.id)).filter(
        Detection.detection_timestamp >= start, Detection.detection_timestamp <= end
    ).group_by(Detection.rule_name).all()
    triggered_rules = [ChartDataPoint(name=r[0], value=r[1]) for r in rule_rows]

    # Executive narrative
    narrative = (
        f"During this {period} reporting period, the Honeypot Trap System captured {total_events} interaction events "
        f"across {unique_sources} unique source hosts. A total of {total_alerts} security alerts were generated. "
        f"The primary attack vector targeted {top_targeted_services[0].service if top_targeted_services else 'simulated services'}, "
        f"demonstrating proactive threat intelligence capture."
    )

    return ReportSummary(
        generated_at=now,
        report_period=period,
        start_date=start,
        end_date=end,
        total_events=total_events,
        unique_sources=unique_sources,
        total_alerts=total_alerts,
        severity_breakdown=severity_breakdown,
        top_targeted_services=top_targeted_services,
        top_threat_sources=top_threat_sources,
        triggered_rules=triggered_rules,
        executive_summary=narrative
    )


@router.get("/export/csv")
def export_csv(
    limit: int = Query(1000, le=10000),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Exports honeypot event telemetry as a downloadable CSV spreadsheet."""
    events = db.query(Event).order_by(desc(Event.timestamp)).limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Event ID", "Timestamp (UTC)", "Source IP", "Source Port",
        "Destination Port", "Protocol", "Service", "Event Type",
        "Severity", "Risk Score", "Session ID", "Raw Payload Sample"
    ])

    for ev in events:
        writer.writerow([
            ev.event_id,
            ev.timestamp.isoformat(),
            ev.source_ip,
            ev.source_port or "",
            ev.destination_port,
            ev.protocol,
            ev.service,
            ev.event_type,
            ev.severity,
            ev.risk_score,
            ev.session_id or "",
            (ev.raw_payload or "")[:100].replace("\n", " ")
        ])

    output.seek(0)
    filename = f"honeypot_telemetry_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/export/json")
def export_json(
    limit: int = Query(500, le=5000),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Exports honeypot event telemetry as structured JSON."""
    events = db.query(Event).order_by(desc(Event.timestamp)).limit(limit).all()
    data = []
    for ev in events:
        data.append({
            "event_id": ev.event_id,
            "timestamp": ev.timestamp.isoformat(),
            "source_ip": ev.source_ip,
            "source_port": ev.source_port,
            "destination_port": ev.destination_port,
            "protocol": ev.protocol,
            "service": ev.service,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "risk_score": ev.risk_score,
            "session_id": ev.session_id,
            "raw_payload": ev.raw_payload
        })

    filename = f"honeypot_telemetry_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
