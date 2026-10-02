from sqlalchemy.orm import Session
from app.core.database import Base, engine, SessionLocal
from app.core.config import settings
from app.core.security import hash_password
from app.core.logger import logger
from app.models.user import User
from app.models.honeypot_service import HoneypotService
from app.models.configuration import SystemConfiguration


def init_db(db: Session = None) -> None:
    """Initialize database tables and seed baseline admin user and honeypot records."""
    Base.metadata.create_all(bind=engine)
    
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
        
    try:
        # Check admin user
        admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        if not admin:
            admin = User(
                username=settings.ADMIN_USERNAME,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
            logger.info(f"Default admin user created: {settings.ADMIN_USERNAME}")

        # Seed Honeypot Services
        default_services = [
            {
                "name": "SSH Honeypot",
                "service_type": "SSH",
                "port": settings.SSH_HONEYPOT_PORT,
                "protocol": "TCP",
                "status": "stopped",
                "description": "Simulated SSH-2.0 daemon logging interactive probes and login attempts",
                "enabled": settings.SSH_HONEYPOT_ENABLED
            },
            {
                "name": "HTTP Honeypot",
                "service_type": "HTTP",
                "port": settings.HTTP_HONEYPOT_PORT,
                "protocol": "TCP",
                "status": "stopped",
                "description": "Deceptive web server capturing path scans, admin probes, and exploits",
                "enabled": settings.HTTP_HONEYPOT_ENABLED
            },
            {
                "name": "FTP Honeypot",
                "service_type": "FTP",
                "port": settings.FTP_HONEYPOT_PORT,
                "protocol": "TCP",
                "status": "stopped",
                "description": "Controlled FTP daemon logging connection attempts and user credentials",
                "enabled": settings.FTP_HONEYPOT_ENABLED
            },
            {
                "name": "Generic TCP Listener",
                "service_type": "TCP",
                "port": settings.TCP_HONEYPOT_PORT,
                "protocol": "TCP",
                "status": "stopped",
                "description": "Low-interaction generic TCP port listener logging payloads and duration",
                "enabled": settings.TCP_HONEYPOT_ENABLED
            }
        ]

        for s_data in default_services:
            svc = db.query(HoneypotService).filter(HoneypotService.name == s_data["name"]).first()
            if not svc:
                svc = HoneypotService(**s_data)
                db.add(svc)
        db.commit()

        # Seed Initial Configuration
        default_configs = [
            ("risk_weights", '{"repeated_attempts": 10, "multi_service": 20, "high_frequency": 20, "suspicious_pattern": 20, "known_indicator": 30}', "Weights applied for heuristic risk scoring"),
            ("detection_thresholds", '{"brute_force_threshold": 3, "high_freq_window_sec": 10, "high_freq_count": 10, "port_scan_count": 3}', "Thresholds for rule triggers")
        ]
        for key, val, desc in default_configs:
            cfg = db.query(SystemConfiguration).filter(SystemConfiguration.key == key).first()
            if not cfg:
                db.add(SystemConfiguration(key=key, value_json=val, description=desc))
        db.commit()
        logger.info("Database initialized successfully.")
    except Exception as e:
        db.rollback()
        logger.error(f"Error initializing database: {e}")
        raise
    finally:
        if close_db:
            db.close()


if __name__ == "__main__":
    init_db()
