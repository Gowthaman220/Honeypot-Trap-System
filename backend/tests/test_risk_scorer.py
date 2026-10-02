from app.models.event import Event
from app.models.detection import Detection
from app.services.risk_scorer import risk_scorer


def test_baseline_risk_calculation():
    event = Event(event_type="CONNECTION", raw_payload="")
    score, severity, factors = risk_scorer.calculate_score(event, [])
    assert score == 5
    assert severity == "LOW"
    assert len(factors) == 1


def test_elevated_risk_with_detections():
    event = Event(event_type="SUSPICIOUS_REQUEST", raw_payload="exploit_test")
    detections = [
        Detection(rule_id="R005", rule_name="Suspicious HTTP", severity="HIGH", score=25, evidence="test"),
        Detection(rule_id="R006", rule_name="Command Pattern", severity="CRITICAL", score=30, evidence="test")
    ]
    score, severity, factors = risk_scorer.calculate_score(event, detections)
    assert score >= 70
    assert severity in ["HIGH", "CRITICAL"]
    assert len(factors) >= 3


def test_score_clamping():
    event = Event(event_type="COMMAND_ATTEMPT", raw_payload="malicious_test_marker")
    detections = [
        Detection(rule_id="R001", rule_name="R1", severity="CRITICAL", score=40, evidence="e"),
        Detection(rule_id="R002", rule_name="R2", severity="CRITICAL", score=40, evidence="e"),
        Detection(rule_id="R006", rule_name="R6", severity="CRITICAL", score=40, evidence="e")
    ]
    score, severity, _ = risk_scorer.calculate_score(event, detections)
    assert score <= 100
    assert severity == "CRITICAL"
