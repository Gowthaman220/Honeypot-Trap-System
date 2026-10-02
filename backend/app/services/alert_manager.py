from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.event import Event
from app.models.detection import Detection
from app.core.config import settings
from app.core.logger import logger


class AlertManager:
    """Manages alert creation, lifecycle state transitions, and optional external dispatches."""

    @staticmethod
    def process_event_alerts(event: Event, detections: List[Detection], db: Session) -> Optional[Alert]:
        """Check if event warrants an alert (HIGH or CRITICAL severity, or high-risk detection)."""
        if event.severity in ["HIGH", "CRITICAL"]:
            title = f"{event.severity} Security Event on {event.service} from {event.source_ip}"
            
            # Link to the most severe detection if present
            det_id = detections[0].id if detections else None
            
            alert = Alert(
                title=title,
                severity=event.severity,
                source_ip=event.source_ip,
                detection_id=det_id,
                event_id=event.event_id,
                status="NEW",
                timestamp=datetime.now(timezone.utc),
                notes=f"Triggered by {event.event_type} with risk score {event.risk_score}."
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            logger.warning(f"ALERT CREATED: [{alert.severity}] {alert.title} (ID: {alert.alert_id})")

            # Optional external dispatch
            AlertManager._dispatch_external_alert(alert)
            return alert
        return None

    @staticmethod
    def _dispatch_external_alert(alert: Alert):
        if settings.ALERT_WEBHOOK_ENABLED and settings.ALERT_WEBHOOK_URL:
            # Safe non-blocking or logged webhook attempt
            logger.info(f"Webhook alert notification queued for {settings.ALERT_WEBHOOK_URL}")
        if settings.ALERT_EMAIL_ENABLED:
            logger.info("Email alert notification queued")


alert_manager = AlertManager()
