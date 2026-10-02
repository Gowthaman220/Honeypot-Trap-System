import asyncio
import uuid
from typing import Optional
from app.core.database import SessionLocal
from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor
from app.core.logger import logger


class SSHHoneypot:
    """
    Controlled, safe SSH Honeypot.
    Emulates an OpenSSH daemon handshake, captures authentication probes and client banners,
    and safely rejects all credentials without executing commands or granting system access.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 2222):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.is_running = False
        self.banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_address = writer.get_extra_info("peername")
        if not client_address:
            writer.close()
            return

        source_ip, source_port = client_address[0], client_address[1]
        session_id = str(uuid.uuid4())
        logger.info(f"[SSH Honeypot] Connection opened from {source_ip}:{source_port} (Session: {session_id})")

        # 1. Record incoming connection
        db = SessionLocal()
        try:
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_port=self.port,
                    protocol="TCP",
                    service="SSH Honeypot",
                    event_type="CONNECTION",
                    session_id=session_id,
                    metadata={"stage": "initial_handshake", "banner_sent": self.banner.decode().strip()}
                ),
                db
            )
        except Exception as e:
            logger.error(f"[SSH Honeypot] Error recording connection event: {e}")
        finally:
            db.close()

        # 2. Protocol exchange
        try:
            writer.write(self.banner)
            await writer.drain()

            # Read client banner/identification
            client_data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
            client_banner = client_data.decode("utf-8", errors="replace").strip()

            db = SessionLocal()
            try:
                # Analyze probe
                probe_type = "FAILED_LOGIN"
                simulated_username = "ssh_client_probe"
                
                # Check if password probe or raw probe
                raw_str = client_data.hex()
                if "root" in client_banner.lower() or "admin" in client_banner.lower() or "user" in client_banner.lower():
                    simulated_username = "extracted_probe_user"

                event_processor.process_raw_event(
                    RawEventInput(
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_port=self.port,
                        protocol="TCP",
                        service="SSH Honeypot",
                        event_type=probe_type,
                        session_id=session_id,
                        metadata={
                            "client_banner": client_banner[:200],
                            "attempted_user": simulated_username,
                            "auth_result": "rejected"
                        },
                        raw_payload=client_banner[:500]
                    ),
                    db
                )
            except Exception as e:
                logger.error(f"[SSH Honeypot] Error recording auth probe: {e}")
            finally:
                db.close()

            # Emulate authentication failure packet
            writer.write(b"\x00\x00\x00\x01\x0b")  # Safe dummy disconnect packet
            await writer.drain()

        except asyncio.TimeoutError:
            logger.debug(f"[SSH Honeypot] Timeout on client {source_ip}:{source_port}")
        except Exception as e:
            logger.debug(f"[SSH Honeypot] Client handler exception: {e}")
        finally:
            # End session
            db = SessionLocal()
            try:
                event_processor.process_raw_event(
                    RawEventInput(
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_port=self.port,
                        protocol="TCP",
                        service="SSH Honeypot",
                        event_type="SESSION_END",
                        session_id=session_id
                    ),
                    db
                )
            except Exception:
                pass
            finally:
                db.close()

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        if self.is_running:
            return
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.is_running = True
        logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")

    async def stop(self):
        if not self.is_running or not self.server:
            return
        self.server.close()
        await self.server.wait_closed()
        self.is_running = False
        logger.info(f"SSH Honeypot on port {self.port} stopped.")
