from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event


class MultipleServicesTargetedRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R004",
            name="Multiple Services Targeted",
            description="Detects an external host actively probing multiple distinct honeypot services (e.g. SSH, HTTP, FTP)",
            severity="HIGH",
            score=20,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        # Look back 15 minutes
        time_window = datetime.now(timezone.utc) - timedelta(minutes=15)
        distinct_services = db.query(Event.service).filter(
            Event.source_ip == event.source_ip,
            Event.timestamp >= time_window
        ).distinct().all()

        services_list = [s[0] for s in distinct_services if s[0]]
        if event.service not in services_list:
            services_list.append(event.service)

        # Trigger if >= 2 distinct honeypot services targeted
        if len(services_list) >= 2:
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Multi-service reconnaissance observed from {event.source_ip}. Services contacted: {', '.join(services_list)}."
            )
        return None
