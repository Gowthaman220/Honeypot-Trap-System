from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor


def test_event_processing_and_persistence(db_session):
    raw = RawEventInput(
        source_ip="10.0.0.99",
        source_port=44552,
        destination_port=8080,
        protocol="TCP",
        service="HTTP Honeypot",
        event_type="HTTP_REQUEST",
        metadata={"path": "/index.html"}
    )
    event, detections, alert = event_processor.process_raw_event(raw, db_session)

    assert event.id is not None
    assert event.source_ip == "10.0.0.99"
    assert event.service == "HTTP Honeypot"
    assert event.risk_score >= 0


def test_events_api_pagination_and_filtering(client, auth_headers, db_session):
    # Insert multiple test events
    for i in range(5):
        event_processor.process_raw_event(
            RawEventInput(
                source_ip=f"10.0.0.{i+1}",
                source_port=50000 + i,
                destination_port=2222,
                protocol="TCP",
                service="SSH Honeypot",
                event_type="CONNECTION"
            ),
            db_session
        )

    response = client.get("/api/events?page=1&page_size=3", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 3
    assert data["total"] >= 5
    assert data["page"] == 1


def test_event_detail_api(client, auth_headers, db_session):
    raw = RawEventInput(
        source_ip="172.16.0.42",
        destination_port=8080,
        service="HTTP Honeypot",
        event_type="SUSPICIOUS_REQUEST",
        metadata={"path": "/wp-login.php"},
        raw_payload="GET /wp-login.php HTTP/1.1"
    )
    ev, _, _ = event_processor.process_raw_event(raw, db_session)

    response = client.get(f"/api/events/{ev.event_id}", headers=auth_headers)
    assert response.status_code == 200
    detail = response.json()
    assert detail["event_id"] == ev.event_id
    assert detail["source_ip"] == "172.16.0.42"
