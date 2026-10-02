from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.core.database import Base


class HoneypotService(Base):
    __tablename__ = "honeypot_services"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, index=True, nullable=False)
    service_type = Column(String(30), nullable=False)  # SSH, HTTP, FTP, TCP
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="TCP", nullable=False)
    status = Column(String(20), default="stopped", nullable=False)  # running, stopped, error
    description = Column(String(255), nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    event_count = Column(Integer, default=0, nullable=False)
    last_activity = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
