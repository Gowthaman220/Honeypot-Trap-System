import asyncio
import uuid
import time
from typing import Optional
from app.core.database import SessionLocal
from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor
from app.core.logger import logger


class GenericTCPHoneypot:
    """
    Controlled, generic low-interaction TCP Honeypot.
    Captures raw probes, banner queries, port scans, and session duration.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.is_running = False

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_address = writer.get_extra_info("peername")
        if not client_address:
            writer.close()
            return

        source_ip, source_port = client_address[0], client_address[1]
        session_id = str(uuid.uuid4())
        start_time = time.time()
        logger.info(f"[Generic TCP Honeypot] Connection opened from {source_ip}:{source_port}")

        # Record initial connection
        db = SessionLocal()
        try:
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_port=self.port,
                    protocol="TCP",
                    service="Generic TCP Listener",
                    event_type="CONNECTION",
                    session_id=session_id,
                    metadata={"target_port": self.port}
                ),
                db
            )
        except Exception as e:
            logger.error(f"[Generic TCP Honeypot] Error recording event: {e}")
        finally:
            db.close()

        try:
            # Send brief prompt or banner
            writer.write(b"Service Ready.\r\n")
            await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
            if data:
                payload_str = data.decode("utf-8", errors="replace").strip()
                db = SessionLocal()
                try:
                    event_processor.process_raw_event(
                        RawEventInput(
                            source_ip=source_ip,
                            source_port=source_port,
                            destination_port=self.port,
                            protocol="TCP",
                            service="Generic TCP Listener",
                            event_type="COMMAND_ATTEMPT",
                            session_id=session_id,
                            metadata={"bytes_received": len(data)},
                            raw_payload=payload_str[:500]
                        ),
                        db
                    )
                except Exception as e:
                    logger.error(f"[Generic TCP Honeypot] Error recording payload: {e}")
                finally:
                    db.close()

                writer.write(b"Command not recognized.\r\n")
                await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"[Generic TCP Honeypot] Handler error: {e}")
        finally:
            # Record session termination
            db = SessionLocal()
            try:
                event_processor.process_raw_event(
                    RawEventInput(
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_port=self.port,
                        protocol="TCP",
                        service="Generic TCP Listener",
                        event_type="SESSION_END",
                        session_id=session_id,
                        metadata={"duration": time.time() - start_time}
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
        logger.info(f"Generic TCP Honeypot listening on {self.host}:{self.port}")

    async def stop(self):
        if not self.is_running or not self.server:
            return
        self.server.close()
        await self.server.wait_closed()
        self.is_running = False
        logger.info(f"Generic TCP Honeypot on port {self.port} stopped.")
