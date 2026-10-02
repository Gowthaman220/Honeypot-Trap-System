from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor
from app.detection.engine import detection_engine


def test_suspicious_http_detection_r005(db_session):
    raw = RawEventInput(
        source_ip="10.10.10.10",
        destination_port=8080,
        service="HTTP Honeypot",
        event_type="SUSPICIOUS_REQUEST",
        metadata={"path": "/.env", "user_agent": "sqlmap/1.4"},
        raw_payload="GET /.env HTTP/1.1\r\nUser-Agent: sqlmap/1.4"
    )
    event, detections, _ = event_processor.process_raw_event(raw, db_session)
    rule_ids = [d.rule_id for d in detections]
    assert "R005" in rule_ids


def test_command_pattern_detection_r006(db_session):
    raw = RawEventInput(
        source_ip="10.10.10.20",
        destination_port=8080,
        service="HTTP Honeypot",
        event_type="COMMAND_ATTEMPT",
        raw_payload="GET /cgi-bin/test?cmd=cat%20/etc/passwd HTTP/1.1"
    )
    event, detections, _ = event_processor.process_raw_event(raw, db_session)
    rule_ids = [d.rule_id for d in detections]
    assert "R006" in rule_ids


def test_repeated_failed_auth_r002(db_session):
    ip = "192.168.1.88"
    for _ in range(3):
        event_processor.process_raw_event(
            RawEventInput(
                source_ip=ip,
                destination_port=2222,
                service="SSH Honeypot",
                event_type="FAILED_LOGIN",
                metadata={"attempted_user": "root"}
            ),
            db_session
        )

    # 4th failure must trigger R002
    event, detections, _ = event_processor.process_raw_event(
        RawEventInput(
            source_ip=ip,
            destination_port=2222,
            service="SSH Honeypot",
            event_type="FAILED_LOGIN",
            metadata={"attempted_user": "admin"}
        ),
        db_session
    )
    rule_ids = [d.rule_id for d in detections]
    assert "R002" in rule_ids


def test_port_scan_detection_r007(db_session):
    ip = "172.16.1.55"
    for port in [2222, 8080]:
        event_processor.process_raw_event(
            RawEventInput(
                source_ip=ip,
                destination_port=port,
                service="Honeypot Service",
                event_type="CONNECTION"
            ),
            db_session
        )

    # 3rd port probe
    event, detections, _ = event_processor.process_raw_event(
        RawEventInput(
            source_ip=ip,
            destination_port=2121,
            service="FTP Honeypot",
            event_type="CONNECTION"
        ),
        db_session
    )
    rule_ids = [d.rule_id for d in detections]
    assert "R007" in rule_ids
