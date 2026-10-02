import json
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List
from sqlalchemy.orm import Session
from app.models.event import Event
from app.models.session import Session as DBSession
from app.models.honeypot_service import HoneypotService
from app.schemas.event import RawEventInput
from app.detection.engine import detection_engine
from app.services.risk_scorer import risk_scorer
from app.services.alert_manager import alert_manager
from app.services.ip_tracker import ip_tracker
from app.services.websocket_manager import ws_manager
from app.core.logger import logger


class EventProcessor:
    """
    Central event processing pipeline.
    Coordinates normalization, persistence, threat detection, risk scoring,
    session lifecycle, IP intelligence, alert generation, and real-time broadcasting.
    """

    @staticmethod
    def process_raw_event(raw: RawEventInput, db: Session) -> Tuple[Event, List[Any], Optional[Any]]:
        now = datetime.now(timezone.utc)
        
        # 1. Normalize session
        session_id = raw.session_id or str(uuid.uuid4())
        session_record = db.query(DBSession).filter(DBSession.session_id == session_id).first()
        if not session_record:
            session_record = DBSession(
                session_id=session_id,
                source_ip=raw.source_ip,
                service=raw.service,
                start_time=now,
                is_active=True,
                duration_seconds=0.0,
                event_count=1
            )
            db.add(session_record)
        else:
            session_record.event_count += 1
            if session_record.start_time:
                # Handle naive vs aware datetime safely
                start = session_record.start_time
                if start.tzinfo is None:
                    start = start.replace(tzinfo=timezone.utc)
                session_record.duration_seconds = max(0.0, (now - start).total_seconds())
            if raw.event_type == "SESSION_END":
                session_record.is_active = False
                session_record.end_time = now

        # 2. Metadata serialization
        meta_str = None
        if raw.metadata:
            meta_str = json.dumps(raw.metadata)

        # 3. Create baseline event
        event = Event(
            event_id=str(uuid.uuid4()),
            timestamp=now,
            source_ip=raw.source_ip,
            source_port=raw.source_port,
            destination_port=raw.destination_port,
            protocol=raw.protocol.upper(),
            service=raw.service,
            event_type=raw.event_type.upper(),
            severity="LOW",
            risk_score=0,
            session_id=session_id,
            metadata_json=meta_str,
            raw_payload=raw.raw_payload[:2000] if raw.raw_payload else None,
            created_at=now
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        # 4. Update honeypot service metrics
        svc = db.query(HoneypotService).filter(HoneypotService.port == raw.destination_port).first()
        if not svc:
            svc = db.query(HoneypotService).filter(HoneypotService.name.ilike(f"%{raw.service}%")).first()
        if svc:
            svc.event_count += 1
            svc.last_activity = now
            db.commit()

        # 5. Evaluate event against detection rules
        detections = detection_engine.evaluate_event(event, db)

        # 6. Calculate heuristic risk score & severity
        score, severity, scoring_factors = risk_scorer.calculate_score(event, detections)
        event.risk_score = score
        event.severity = severity

        # Enrich metadata with scoring factors for transparency
        try:
            m = json.loads(event.metadata_json) if event.metadata_json else {}
            m["scoring_factors"] = scoring_factors
            event.metadata_json = json.dumps(m)
        except Exception:
            pass

        db.commit()
        db.refresh(event)

        # 7. Update IP threat profile
        ip_tracker.update_ip_stat(event, db)

        # 8. Check and generate security alerts
        alert = alert_manager.process_event_alerts(event, detections, db)

        # 9. Asynchronous WebSocket broadcast (if loop is running)
        EventProcessor._queue_ws_broadcast(event, detections, alert)

        logger.info(
            f"Event Processed: [{event.severity}] {event.service} from {event.source_ip} - "
            f"Score: {event.risk_score} (Detections: {len(detections)})"
        )

        return event, detections, alert

    @staticmethod
    def _queue_ws_broadcast(event: Event, detections: List[Any], alert: Optional[Any]):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            payload = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source_ip": event.source_ip,
                "source_port": event.source_port,
                "destination_port": event.destination_port,
                "protocol": event.protocol,
                "service": event.service,
                "event_type": event.event_type,
                "severity": event.severity,
                "risk_score": event.risk_score,
                "session_id": event.session_id,
                "detections_count": len(detections),
                "has_alert": alert is not None
            }
            loop.create_task(ws_manager.broadcast("NEW_EVENT", payload))
            if alert:
                alert_payload = {
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "source_ip": alert.source_ip,
                    "timestamp": alert.timestamp.isoformat(),
                    "status": alert.status
                }
                loop.create_task(ws_manager.broadcast("NEW_ALERT", alert_payload))


event_processor = EventProcessor()
