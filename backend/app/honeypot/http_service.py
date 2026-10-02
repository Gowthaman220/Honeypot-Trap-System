import asyncio
import uuid
import urllib.parse
from typing import Optional
from app.core.database import SessionLocal
from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor
from app.core.logger import logger


LOGIN_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Gateway - Sign In</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; width: 100%; max-width: 400px; padding: 32px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
        .logo { font-size: 20px; font-weight: bold; color: #38bdf8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; text-align: center; }
        .subtitle { font-size: 13px; color: #94a3b8; text-align: center; margin-bottom: 24px; }
        .error-box { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #fca5a5; font-size: 13px; padding: 10px 14px; border-radius: 8px; margin-bottom: 20px; display: flex; align-items: center; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #cbd5e1; margin-bottom: 6px; letter-spacing: 0.5px; }
        input { width: 100%; padding: 10px 12px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; font-size: 14px; outline: none; transition: border-color 0.2s; }
        input:focus { border-color: #38bdf8; }
        button { width: 100%; padding: 12px; background: #0284c7; hover:background: #0369a1; border: none; border-radius: 6px; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-top: 8px; }
        button:hover { background: #0369a1; }
        .footer { margin-top: 24px; font-size: 11px; text-align: center; color: #64748b; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">Corporate Internal Portal</div>
        <div class="subtitle">Secure Gateway &bull; Authorized Personnel Only</div>
        __ERROR_BLOCK__
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username / Corporate ID</label>
                <input type="text" name="username" placeholder="user@corp.internal" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••••••" required>
            </div>
            <button type="submit">Authenticate Session</button>
        </form>
        <div class="footer">Unauthorized access attempts are monitored and recorded.</div>
    </div>
</body>
</html>
"""


class HTTPHoneypot:
    """
    Controlled, safe HTTP Honeypot.
    Simulates a corporate administrative portal, captures paths, headers, methods,
    POST form credentials, and user-agents, and safely responds with deceptive mock pages.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
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

        try:
            request_data = await asyncio.wait_for(reader.read(8192), timeout=6.0)
            if not request_data:
                writer.close()
                return

            request_text = request_data.decode("utf-8", errors="replace")
            header_part, _, body_part = request_text.partition("\r\n\r\n")

            lines = header_part.split("\r\n")
            first_line = lines[0] if lines else ""
            parts = first_line.split(" ")
            method = parts[0].upper() if len(parts) > 0 else "UNKNOWN"
            full_path = parts[1] if len(parts) > 1 else "/"
            http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if not line:
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            user_agent = headers.get("user-agent", "Unknown")
            path_only = full_path.split("?")[0]

            # Check if this is an authentication attempt (POST or form submission)
            is_login_attempt = False
            attempted_user = "unknown"

            combined_payload = f"{full_path} {body_part}"
            parsed_params = {}
            try:
                # Parse query params or POST form body
                if body_part:
                    parsed_params.update(urllib.parse.parse_qs(body_part))
                if "?" in full_path:
                    parsed_params.update(urllib.parse.parse_qs(full_path.split("?", 1)[1]))
            except Exception:
                pass

            # Check for credential keys
            for user_key in ["username", "user", "log", "email", "login"]:
                if user_key in parsed_params:
                    attempted_user = parsed_params[user_key][0]
                    is_login_attempt = True
                    break

            if method == "POST" or is_login_attempt or "wp-login" in path_only or "/admin" in path_only:
                if method == "POST" or is_login_attempt:
                    event_type = "FAILED_LOGIN"
                else:
                    event_type = "SUSPICIOUS_REQUEST"
            else:
                # Check suspicious keywords
                is_suspicious = False
                suspicious_keywords = [
                    "/wp-", "/admin", "/.env", "/phpmyadmin", "/actuator", "/shell",
                    "/config", "/etc/passwd", "eval", "cmd", "select", "union", "<script"
                ]
                for kw in suspicious_keywords:
                    if kw in full_path.lower() or kw in body_part.lower():
                        is_suspicious = True
                        break
                event_type = "SUSPICIOUS_REQUEST" if is_suspicious else "HTTP_REQUEST"

            # Sanitized payload snippet
            safe_payload_snippet = f"{method} {full_path} HTTP/1.1\r\n"
            if is_login_attempt:
                safe_payload_snippet += f"Form Submission -> Attempted User: '{attempted_user}' [Password Redacted]"
            elif body_part:
                safe_payload_snippet += f"Body: {body_part[:300]}"

            # Ingest into event processor
            db = SessionLocal()
            try:
                event_processor.process_raw_event(
                    RawEventInput(
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_port=self.port,
                        protocol="TCP",
                        service="HTTP Honeypot",
                        event_type=event_type,
                        session_id=session_id,
                        metadata={
                            "method": method,
                            "path": full_path,
                            "http_version": http_version,
                            "user_agent": user_agent,
                            "attempted_user": attempted_user if is_login_attempt else None,
                            "auth_result": "rejected" if is_login_attempt else None
                        },
                        raw_payload=safe_payload_snippet
                    ),
                    db
                )
            except Exception as e:
                logger.error(f"[HTTP Honeypot] Error recording event: {e}")
            finally:
                db.close()

            # Render safe deceptive response
            if method == "POST" and (is_login_attempt or "login" in path_only or "admin" in path_only):
                # Return login failure page
                err_html = '<div class="error-box">Authentication Failed: Invalid username or password. This incident has been logged.</div>'
                body = LOGIN_HTML_TEMPLATE.replace("__ERROR_BLOCK__", err_html)
                status_line = "HTTP/1.1 200 OK"
            elif path_only in ["/", "/admin", "/login", "/wp-login.php", "/wp-admin", "/portal", "/signin"]:
                # Return pristine login portal
                body = LOGIN_HTML_TEMPLATE.replace("__ERROR_BLOCK__", "")
                status_line = "HTTP/1.1 200 OK"
            elif "/.env" in full_path.lower() or "/config" in full_path.lower():
                body = "# Safe Honeypot Simulator\nAPP_ENV=production\nDATABASE_URL=sqlite:///./prod.db\nSECRET_KEY=honey-decoy-token\n"
                status_line = "HTTP/1.1 200 OK"
            else:
                body = "<html><head><title>Internal Portal</title></head><body><h2>System Ready</h2><p>Corporate access active.</p></body></html>"
                status_line = "HTTP/1.1 200 OK"

            response = (
                f"{status_line}\r\n"
                f"Server: Apache/2.4.52 (Ubuntu)\r\n"
                f"Content-Type: text/html; charset=UTF-8\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
            writer.write(response.encode("utf-8"))
            await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"[HTTP Honeypot] Handler error: {e}")
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
        logger.info(f"HTTP Honeypot listening on {self.host}:{self.port}")

    async def stop(self):
        if not self.is_running or not self.server:
            return
        self.server.close()
        await self.server.wait_closed()
        self.is_running = False
        logger.info(f"HTTP Honeypot on port {self.port} stopped.")
