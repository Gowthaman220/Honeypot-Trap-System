import re
import urllib.parse
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event

COMMAND_INDICATORS = [
    r"cat\s+/etc/passwd",
    r"cat\s+/etc/shadow",
    r"whoami",
    r"id\s*$",
    r"uname\s+-a",
    r"wget\s+http",
    r"curl\s+-s",
    r"powershell",
    r"cmd\.exe",
    r"chmod\s+\+x",
    r"bash\s+-i",
    r"/bin/sh",
    r"nc\s+-e",
    r"systeminfo",
    r"net\s+user",
    r"sudo\s+su",
    r"crontab\s+-l"
]


class SuspiciousCommandPatternRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R006",
            name="Suspicious Command Pattern",
            description="Detects post-exploitation command execution, reconnaissance commands, and reverse shell triggers",
            severity="CRITICAL",
            score=30,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        raw = (event.raw_payload or "") + " " + (event.metadata_json or "")
        # Decode URL-encoded sequences (e.g., %20 -> space)
        decoded = urllib.parse.unquote(raw)
        payload = f"{raw} {decoded}"
        matched = []

        for pattern in COMMAND_INDICATORS:
            if re.search(pattern, payload, re.IGNORECASE):
                matched.append(pattern)

        if matched:
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Observed reconnaissance/exploitation command patterns: {', '.join(matched[:4])} originating from {event.source_ip}."
            )
        return None
