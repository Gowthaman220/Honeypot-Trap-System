from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.detection.base import DetectionRule, DetectionResult
from app.detection.rules import (
    RepeatedConnectionsRule,
    FailedAuthenticationRule,
    HighRequestFrequencyRule,
    MultipleServicesTargetedRule,
    SuspiciousHTTPRequestRule,
    SuspiciousCommandPatternRule,
    PortScanPatternRule,
    LongSessionRule
)
from app.models.event import Event
from app.models.detection import Detection
from app.core.logger import logger


class ThreatDetectionEngine:
    def __init__(self):
        self.rules: Dict[str, DetectionRule] = {}
        self._register_default_rules()

    def _register_default_rules(self):
        rules = [
            RepeatedConnectionsRule(),
            FailedAuthenticationRule(),
            HighRequestFrequencyRule(),
            MultipleServicesTargetedRule(),
            SuspiciousHTTPRequestRule(),
            SuspiciousCommandPatternRule(),
            PortScanPatternRule(),
            LongSessionRule()
        ]
        for rule in rules:
            self.register_rule(rule)

    def register_rule(self, rule: DetectionRule):
        self.rules[rule.rule_id] = rule

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled
            return True
        return False

    def get_all_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "score": r.score,
                "enabled": r.enabled
            }
            for r in self.rules.values()
        ]

    def evaluate_event(self, event: Event, db: Session) -> List[Detection]:
        """Evaluate an incoming event against all registered rules and store matches."""
        triggered_detections: List[Detection] = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue
            try:
                result: Optional[DetectionResult] = rule.evaluate(event, db)
                if result:
                    detection = Detection(
                        rule_id=result.rule_id,
                        rule_name=result.rule_name,
                        description=result.description,
                        severity=result.severity,
                        score=result.score,
                        evidence=result.evidence,
                        event_id=event.event_id,
                        source_ip=event.source_ip,
                        detection_timestamp=event.timestamp
                    )
                    db.add(detection)
                    triggered_detections.append(detection)
                    logger.warning(f"Detection rule triggered: [{result.rule_id}] {result.rule_name} for IP {event.source_ip}")
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}")

        if triggered_detections:
            db.commit()
            for d in triggered_detections:
                db.refresh(d)

        return triggered_detections


detection_engine = ThreatDetectionEngine()
