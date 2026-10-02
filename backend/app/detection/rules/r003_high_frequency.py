from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event


class HighRequestFrequencyRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R003",
            name="High Request Frequency / Burst",
            description="Detects rapid automated request bursts indicating automated vulnerability scanners or DoS probing",
            severity="MEDIUM",
            score=20,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        # Look back 10 seconds
        time_window = datetime.now(timezone.utc) - timedelta(seconds=10)
        burst_count = db.query(func.count(Event.id)).filter(
            Event.source_ip == event.source_ip,
            Event.timestamp >= time_window
        ).scalar() or 0

        # Trigger threshold: > 8 requests in 10 seconds
        if burst_count >= 8:
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Burst rate threshold exceeded: {burst_count} events generated from {event.source_ip} within a 10-second interval."
            )
        return None
