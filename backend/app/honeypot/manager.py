import asyncio
from typing import Dict, Any, List, Optional
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.honeypot_service import HoneypotService
from app.honeypot.ssh_service import SSHHoneypot
from app.honeypot.http_service import HTTPHoneypot
from app.honeypot.ftp_service import FTPHoneypot
from app.honeypot.tcp_service import GenericTCPHoneypot
from app.core.logger import logger


class HoneypotManager:
    """
    Central Honeypot lifecycle manager.
    Coordinates starting, stopping, and health monitoring of all honeypot services.
    """

    def __init__(self):
        self.services = {
            "SSH Honeypot": SSHHoneypot(port=settings.SSH_HONEYPOT_PORT),
            "HTTP Honeypot": HTTPHoneypot(port=settings.HTTP_HONEYPOT_PORT),
            "FTP Honeypot": FTPHoneypot(port=settings.FTP_HONEYPOT_PORT),
            "Generic TCP Listener": GenericTCPHoneypot(port=settings.TCP_HONEYPOT_PORT),
        }

    async def start_all(self):
        """Starts all enabled honeypots."""
        db = SessionLocal()
        try:
            for name, service in self.services.items():
                svc_record = db.query(HoneypotService).filter(HoneypotService.name == name).first()
                should_enable = svc_record.enabled if svc_record else True

                if should_enable:
                    try:
                        await service.start()
                        if svc_record:
                            svc_record.status = "running"
                        logger.info(f"Started honeypot service: {name}")
                    except Exception as e:
                        if svc_record:
                            svc_record.status = "error"
                        logger.error(f"Failed to start honeypot service {name}: {e}")
            db.commit()
        finally:
            db.close()

    async def stop_all(self):
        """Stops all honeypots."""
        db = SessionLocal()
        try:
            for name, service in self.services.items():
                try:
                    await service.stop()
                    svc_record = db.query(HoneypotService).filter(HoneypotService.name == name).first()
                    if svc_record:
                        svc_record.status = "stopped"
                    logger.info(f"Stopped honeypot service: {name}")
                except Exception as e:
                    logger.error(f"Error stopping honeypot service {name}: {e}")
            db.commit()
        finally:
            db.close()

    async def start_service(self, name_or_id: str) -> bool:
        db = SessionLocal()
        try:
            # Query by id or name
            svc_record = None
            if str(name_or_id).isdigit():
                svc_record = db.query(HoneypotService).filter(HoneypotService.id == int(name_or_id)).first()
            if not svc_record:
                svc_record = db.query(HoneypotService).filter(HoneypotService.name.ilike(f"%{name_or_id}%")).first()

            if not svc_record or svc_record.name not in self.services:
                return False

            service = self.services[svc_record.name]
            await service.start()
            svc_record.status = "running"
            svc_record.enabled = True
            db.commit()
            return True
        except Exception as e:
            logger.error(f"Error starting service {name_or_id}: {e}")
            return False
        finally:
            db.close()

    async def stop_service(self, name_or_id: str) -> bool:
        db = SessionLocal()
        try:
            svc_record = None
            if str(name_or_id).isdigit():
                svc_record = db.query(HoneypotService).filter(HoneypotService.id == int(name_or_id)).first()
            if not svc_record:
                svc_record = db.query(HoneypotService).filter(HoneypotService.name.ilike(f"%{name_or_id}%")).first()

            if not svc_record or svc_record.name not in self.services:
                return False

            service = self.services[svc_record.name]
            await service.stop()
            svc_record.status = "stopped"
            svc_record.enabled = False
            db.commit()
            return True
        except Exception as e:
            logger.error(f"Error stopping service {name_or_id}: {e}")
            return False
        finally:
            db.close()

    def get_service_statuses(self) -> List[Dict[str, Any]]:
        statuses = []
        for name, service in self.services.items():
            statuses.append({
                "name": name,
                "port": service.port,
                "is_running": service.is_running
            })
        return statuses


honeypot_manager = HoneypotManager()
