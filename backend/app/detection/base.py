from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from sqlalchemy.orm import Session
from app.models.event import Event


@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    score: int
    evidence: str  # Details of why the rule fired


class DetectionRule(ABC):
    def __init__(self, rule_id: str, name: str, description: str, severity: str, score: int, enabled: bool = True):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.score = score
        self.enabled = enabled

    @abstractmethod
    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        """Evaluate an event and return a DetectionResult if triggered, else None."""
        pass
