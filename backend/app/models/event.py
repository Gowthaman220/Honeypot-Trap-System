import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, Index
from app.core.database import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    source_ip = Column(String(45), index=True, nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="TCP", nullable=False)
    service = Column(String(50), index=True, nullable=False)
    event_type = Column(String(50), index=True, nullable=False)
    severity = Column(String(20), index=True, default="LOW", nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)
    session_id = Column(String(64), index=True, nullable=True)
    metadata_json = Column(Text, nullable=True)  # Stores headers, user_agent, path, username, details
    raw_payload = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("idx_events_ip_timestamp", "source_ip", "timestamp"),
        Index("idx_events_service_severity", "service", "severity"),
    )
