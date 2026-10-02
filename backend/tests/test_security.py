import pytest
from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor


def test_sql_injection_resistant_queries(client, auth_headers, db_session):
    # Attempt SQL injection through search parameter
    sqli_payload = "'; DROP TABLE events; --"
    response = client.get(f"/api/events?search={sqli_payload}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data

    # Verify table is still intact and operable
    raw = RawEventInput(
        source_ip="10.0.0.1",
        destination_port=8080,
        service="HTTP Honeypot",
        event_type="HTTP_REQUEST"
    )
    event, _, _ = event_processor.process_raw_event(raw, db_session)
    assert event.id is not None


def test_input_validation_on_event_query(client, auth_headers):
    # Invalid page number (negative or zero)
    response = client.get("/api/events?page=0", headers=auth_headers)
    assert response.status_code == 422

    # Excessive page_size > 100
    response = client.get("/api/events?page_size=500", headers=auth_headers)
    assert response.status_code == 422


def test_unauthenticated_security_barrier(client):
    # Attempt unauthorized access to sensitive administrative routes
    assert client.get("/api/settings").status_code == 401
    assert client.post("/api/honeypots/1/start").status_code == 401
    assert client.post("/api/honeypots/1/stop").status_code == 401
    assert client.get("/api/reports/summary").status_code == 401
