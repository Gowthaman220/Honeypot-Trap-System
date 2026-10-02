import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    title = Column(String(150), nullable=False)
    severity = Column(String(20), index=True, nullable=False)  # HIGH, CRITICAL, MEDIUM
    source_ip = Column(String(45), index=True, nullable=False)
    detection_id = Column(Integer, nullable=True)
    event_id = Column(String(36), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    status = Column(String(20), default="NEW", index=True, nullable=False)  # NEW, ACKNOWLEDGED, RESOLVED
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
