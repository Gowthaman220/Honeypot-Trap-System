from typing import Dict, Any, Tuple, List
from app.core.config import settings
from app.models.event import Event
from app.models.detection import Detection


class RiskScorer:
    """
    Transparent, explainable risk scoring engine.
    Calculates a heuristic risk score (0-100) and severity based on triggered factors.
    """
    
    @staticmethod
    def calculate_score(event: Event, detections: List[Detection]) -> Tuple[int, str, List[Dict[str, Any]]]:
        """
        Calculates heuristic risk score, severity band, and itemized explainable factors.
        Returns: (final_score, severity_label, factor_breakdown)
        """
        score = 0
        factors = []

        # 1. Base score derived from raw event type
        base_scores = {
            "CONNECTION": 5,
            "LOGIN_ATTEMPT": 15,
            "FAILED_LOGIN": 25,
            "HTTP_REQUEST": 10,
            "SUSPICIOUS_REQUEST": 35,
            "COMMAND_ATTEMPT": 45,
            "PORT_SCAN": 35,
            "SESSION_END": 0
        }
        base = base_scores.get(event.event_type.upper(), 10)
        score += base
        factors.append({"factor": "Base Event Type", "contribution": base, "detail": f"Event type is {event.event_type}"})

        # 2. Contributions from triggered detection rules
        for d in detections:
            rule_contribution = 0
            if d.rule_id == "R001":
                rule_contribution = settings.RISK_WEIGHT_REPEATED_ATTEMPTS
            elif d.rule_id == "R002":
                rule_contribution = 25
            elif d.rule_id == "R003":
                rule_contribution = settings.RISK_WEIGHT_HIGH_FREQUENCY
            elif d.rule_id == "R004":
                rule_contribution = settings.RISK_WEIGHT_MULTI_SERVICE
            elif d.rule_id == "R005":
                rule_contribution = settings.RISK_WEIGHT_SUSPICIOUS_PATTERN
            elif d.rule_id == "R006":
                rule_contribution = 30
            elif d.rule_id == "R007":
                rule_contribution = 25
            elif d.rule_id == "R008":
                rule_contribution = 15
            else:
                rule_contribution = d.score or 10

            score += rule_contribution
            factors.append({
                "factor": f"Triggered {d.rule_id}: {d.rule_name}",
                "contribution": rule_contribution,
                "detail": d.evidence
            })

        # 3. Known test indicator heuristic check
        check_text = (event.raw_payload or "").lower()
        if "malicious_test_marker" in check_text or "exploit_poc" in check_text:
            ind_score = settings.RISK_WEIGHT_KNOWN_INDICATOR
            score += ind_score
            factors.append({
                "factor": "Known Test Indicator",
                "contribution": ind_score,
                "detail": "Matched test indicator marker in payload"
            })

        # Clamp between 0 and 100
        final_score = max(0, min(100, score))

        # Severity categorization
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return final_score, severity, factors


risk_scorer = RiskScorer()
