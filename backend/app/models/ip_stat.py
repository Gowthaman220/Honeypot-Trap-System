from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.core.database import Base


class IPStatistic(Base):
    __tablename__ = "ip_statistics"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), unique=True, index=True, nullable=False)
    total_events = Column(Integer, default=1, nullable=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    highest_risk_score = Column(Integer, default=0, nullable=False)
    services_targeted = Column(Text, default="[]", nullable=False)  # JSON list of services
    threat_level = Column(String(20), default="LOW", nullable=False)
    notes = Column(Text, nullable=True)
