from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from app.core.database import Base


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(20), index=True, nullable=False)
    rule_name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=False)
    severity = Column(String(20), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    score = Column(Integer, default=0, nullable=False)
    evidence = Column(Text, nullable=True)  # JSON or text describing matched trigger
    event_id = Column(String(36), index=True, nullable=False)
    source_ip = Column(String(45), index=True, nullable=False)
    detection_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
