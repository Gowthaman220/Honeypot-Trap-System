from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event


class PortScanPatternRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R007",
            name="Port Scanning Pattern",
            description="Detects rapid port scanning across multiple destination honeypot ports by a single host",
            severity="HIGH",
            score=25,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        # Look back 2 minutes
        time_window = datetime.now(timezone.utc) - timedelta(minutes=2)
        distinct_ports = db.query(Event.destination_port).filter(
            Event.source_ip == event.source_ip,
            Event.timestamp >= time_window
        ).distinct().all()

        ports = [p[0] for p in distinct_ports if p[0]]
        if event.destination_port not in ports:
            ports.append(event.destination_port)

        # Trigger threshold: >= 3 distinct destination ports in 2 minutes
        if len(ports) >= 3:
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Port scan pattern detected from {event.source_ip}. Probed destination ports: {', '.join(map(str, sorted(ports)))}."
            )
        return None
