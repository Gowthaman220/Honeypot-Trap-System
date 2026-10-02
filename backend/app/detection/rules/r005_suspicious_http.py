import json
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.detection.base import DetectionRule, DetectionResult
from app.models.event import Event


SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/wp-login.php", "/.env", "/config", "/backup",
    "/phpmyadmin", "/pma", "/actuator", "/actuator/env", "/actuator/health",
    "/api/v1/users", "/shell", "/cmd", "/eval-stdin.php", "/vendor/phpunit",
    "/.git", "/.svn", "/solr", "/jenkins", "/console", "/manager/html",
    "/cgi-bin", "/etc/passwd", "/win.ini", "../", "..\\", "%2e%2e"
]


class SuspiciousHTTPRequestRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R005",
            name="Suspicious HTTP Request Pattern",
            description="Detects web vulnerability scanning, directory traversal attempts, and credential endpoint probes",
            severity="HIGH",
            score=25,
            enabled=True
        )

    def evaluate(self, event: Event, db: Session, context: Optional[Dict[str, Any]] = None) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        matched_patterns = []
        path = ""
        user_agent = ""

        # Check metadata
        if event.metadata_json:
            try:
                meta = json.loads(event.metadata_json)
                path = meta.get("path", "").lower()
                user_agent = meta.get("user_agent", "").lower()
            except Exception:
                pass

        # Check raw payload or path
        check_text = (path + " " + (event.raw_payload or "")).lower()

        for pattern in SUSPICIOUS_PATHS:
            if pattern.lower() in check_text:
                matched_patterns.append(pattern)

        # Check suspicious scanner user agents (sqlmap, nikto, nuclei, gobuster, nmap)
        scanner_agents = ["sqlmap", "nikto", "nuclei", "gobuster", "dirbuster", "nmap", "masscan", "zgrab"]
        for agent in scanner_agents:
            if agent in user_agent:
                matched_patterns.append(f"Scanner User-Agent ({agent})")

        if matched_patterns:
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                description=self.description,
                severity=self.severity,
                score=self.score,
                evidence=f"Detected suspicious web indicators: {', '.join(matched_patterns[:5])} in request from {event.source_ip}."
            )
        return None
