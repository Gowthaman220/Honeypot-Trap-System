import asyncio
import uuid
from typing import Optional
from app.core.database import SessionLocal
from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor
from app.core.logger import logger


class FTPHoneypot:
    """
    Controlled, safe FTP Honeypot.
    Emulates an FTP daemon, records authentication attempts and command exploration,
    and safely rejects all credentials without filesystem exposure.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 2121):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.is_running = False
        self.banner = b"220 ProFTPD 1.3.5 Server (Ubuntu ProFTPD) ready.\r\n"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_address = writer.get_extra_info("peername")
        if not client_address:
            writer.close()
            return

        source_ip, source_port = client_address[0], client_address[1]
        session_id = str(uuid.uuid4())
        logger.info(f"[FTP Honeypot] Connection opened from {source_ip}:{source_port}")

        # Record initial connection
        db = SessionLocal()
        try:
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_port=self.port,
                    protocol="TCP",
                    service="FTP Honeypot",
                    event_type="CONNECTION",
                    session_id=session_id,
                    metadata={"banner": self.banner.decode().strip()}
                ),
                db
            )
        except Exception as e:
            logger.error(f"[FTP Honeypot] Error recording connection: {e}")
        finally:
            db.close()

        try:
            writer.write(self.banner)
            await writer.drain()

            current_user = None

            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=15.0)
                if not line:
                    break

                cmd_text = line.decode("utf-8", errors="replace").strip()
                if not cmd_text:
                    continue

                parts = cmd_text.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break

                elif cmd == "USER":
                    current_user = arg
                    writer.write(f"331 Password required for {arg}\r\n".encode())
                    await writer.drain()

                elif cmd == "PASS":
                    # Record failed authentication attempt
                    db = SessionLocal()
                    try:
                        event_processor.process_raw_event(
                            RawEventInput(
                                source_ip=source_ip,
                                source_port=source_port,
                                destination_port=self.port,
                                protocol="TCP",
                                service="FTP Honeypot",
                                event_type="FAILED_LOGIN",
                                session_id=session_id,
                                metadata={
                                    "username": current_user or "unknown",
                                    "password_length": len(arg),
                                    "auth_result": "rejected"
                                },
                                raw_payload=f"USER {current_user} PASS [REDACTED]"
                            ),
                            db
                        )
                    except Exception as e:
                        logger.error(f"[FTP Honeypot] Error recording auth event: {e}")
                    finally:
                        db.close()

                    writer.write(b"530 Login incorrect.\r\n")
                    await writer.drain()

                elif cmd == "SYST":
                    writer.write(b"215 UNIX Type: L8\r\n")
                    await writer.drain()

                else:
                    # Log unauthorized command attempt
                    db = SessionLocal()
                    try:
                        event_processor.process_raw_event(
                            RawEventInput(
                                source_ip=source_ip,
                                source_port=source_port,
                                destination_port=self.port,
                                protocol="TCP",
                                service="FTP Honeypot",
                                event_type="COMMAND_ATTEMPT",
                                session_id=session_id,
                                metadata={"command": cmd, "argument": arg[:100]},
                                raw_payload=cmd_text[:200]
                            ),
                            db
                        )
                    except Exception:
                        pass
                    finally:
                        db.close()

                    writer.write(b"530 Please login with USER and PASS.\r\n")
                    await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"[FTP Honeypot] Client error: {e}")
        finally:
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
        logger.info(f"FTP Honeypot listening on {self.host}:{self.port}")

    async def stop(self):
        if not self.is_running or not self.server:
            return
        self.server.close()
        await self.server.wait_closed()
        self.is_running = False
        logger.info(f"FTP Honeypot on port {self.port} stopped.")
