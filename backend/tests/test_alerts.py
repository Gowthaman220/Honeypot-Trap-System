from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor
from app.models.alert import Alert


def test_alert_generation_on_critical_event(db_session):
    raw = RawEventInput(
        source_ip="10.0.0.77",
        destination_port=8080,
        service="HTTP Honeypot",
        event_type="COMMAND_ATTEMPT",
        raw_payload="GET /shell?cmd=cat%20/etc/shadow HTTP/1.1"
    )
    event, detections, alert = event_processor.process_raw_event(raw, db_session)
    assert alert is not None
    assert alert.severity in ["HIGH", "CRITICAL"]
    assert alert.status == "NEW"


def test_alert_lifecycle_api(client, auth_headers, db_session):
    raw = RawEventInput(
        source_ip="10.0.0.78",
        destination_port=8080,
        service="HTTP Honeypot",
        event_type="COMMAND_ATTEMPT",
        raw_payload="GET /shell?cmd=whoami HTTP/1.1"
    )
    _, _, alert = event_processor.process_raw_event(raw, db_session)

    # 1. Fetch alerts
    resp = client.get("/api/alerts?status=NEW", headers=auth_headers)
    assert resp.status_code == 200
    alerts = resp.json()
    assert any(a["alert_id"] == alert.alert_id for a in alerts)

    # 2. Acknowledge alert
    ack_resp = client.patch(
        f"/api/alerts/{alert.alert_id}",
        json={"status": "ACKNOWLEDGED", "notes": "Investigating source IP"},
        headers=auth_headers
    )
    assert ack_resp.status_code == 200
    assert ack_resp.json()["status"] == "ACKNOWLEDGED"

    # 3. Resolve alert
    res_resp = client.patch(
        f"/api/alerts/{alert.alert_id}",
        json={"status": "RESOLVED", "notes": "Blocked in border firewall"},
        headers=auth_headers
    )
    assert res_resp.status_code == 200
    assert res_resp.json()["status"] == "RESOLVED"
