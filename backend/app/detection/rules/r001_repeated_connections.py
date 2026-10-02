from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event


class RepeatedConnectionsRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R001",
            name="Repeated Connection Attempts",
            description="Detects anomalous repeated connection attempts from a single source IP within a short window",
            severity="MEDIUM",
            score=15,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        # Look back 60 seconds
        time_window = datetime.now(timezone.utc) - timedelta(seconds=60)
        recent_count = db.query(func.count(Event.id)).filter(
            Event.source_ip == event.source_ip,
            Event.timestamp >= time_window
        ).scalar() or 0

        # Trigger threshold: > 5 connections in 60s
        if recent_count >= 5:
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Source {event.source_ip} made {recent_count} connection attempts across honeypot ports in the last 60 seconds."
            )
        return None
