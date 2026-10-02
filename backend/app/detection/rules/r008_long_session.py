from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event
from app.models.session import Session as DBSession


class LongSessionRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R008",
            name="Abnormally Long Interactive Session",
            description="Detects prolonged active connections where an external client persists an interactive honeypot socket",
            severity="MEDIUM",
            score=15,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled or not event.session_id:
            return None

        # Check session duration
        sess = db.query(DBSession).filter(DBSession.session_id == event.session_id).first()
        if sess and sess.duration_seconds > 180:  # > 3 minutes
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Active session {event.session_id} from {event.source_ip} on service {event.service} exceeded 180 seconds (duration: {int(sess.duration_seconds)}s)."
            )
        return None
