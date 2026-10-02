from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float
from app.core.database import Base


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    source_ip = Column(String(45), index=True, nullable=False)
    service = Column(String(50), nullable=False)
    start_time = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0, nullable=False)
    event_count = Column(Integer, default=1, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
