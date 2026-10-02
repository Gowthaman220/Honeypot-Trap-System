from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event


class FailedAuthenticationRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R002",
            name="Repeated Failed Authentication",
            description="Detects brute-force authentication attacks targeting login interfaces (SSH, FTP, HTTP)",
            severity="HIGH",
            score=25,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        if event.event_type not in ["FAILED_LOGIN", "LOGIN_ATTEMPT"]:
            return None

        # Look back 5 minutes for authentication failures from this IP
        time_window = datetime.now(timezone.utc) - timedelta(minutes=5)
        failed_count = db.query(func.count(Event.id)).filter(
            Event.source_ip == event.source_ip,
            Event.event_type.in_(["FAILED_LOGIN", "LOGIN_ATTEMPT"]),
            Event.timestamp >= time_window
        ).scalar() or 0

        # Trigger threshold: >= 3 failed logins
        if failed_count >= 3:
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Source {event.source_ip} reached {failed_count} repeated failed authentication attempts in the past 5 minutes (target service: {event.service})."
            )
        return None
