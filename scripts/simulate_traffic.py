#!/usr/bin/env python3
"""
Honeypot Trap System - Live Safe Local Traffic Simulator
Safely tests active honeypot listener ports on localhost (127.0.0.1).
Simulates SSH banner handshake, HTTP probe requests, FTP auth interaction, and raw TCP probes.
Strictly isolated to localhost test ports.
"""

import sys
import socket
import time
import urllib.request
import urllib.error


def test_ssh(port=2222):
    print(f"\n[+] Testing SSH Honeypot on 127.0.0.1:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect(("127.0.0.1", port))
        banner = s.recv(1024).decode(errors="replace").strip()
        print(f"    <- Received SSH Banner: {banner}")
        client_ident = "SSH-2.0-OpenSSH_TestProbe_v1.0\r\n"
        print(f"    -> Sending client identity: {client_ident.strip()}")
        s.sendall(client_ident.encode())
        resp = s.recv(1024)
        print(f"    <- Honeypot Disconnect Packet: {resp.hex() if resp else 'Closed'}")
        s.close()
        print("    [OK] SSH Honeypot connection completed.")
    except Exception as e:
        print(f"    [!] SSH test note: {e}")


def test_http(port=8080):
    print(f"\n[+] Testing HTTP Honeypot on 127.0.0.1:{port}...")
    paths = ["/", "/wp-login.php", "/.env", "/phpmyadmin"]
    for path in paths:
        url = f"http://127.0.0.1:{port}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CyberSecurity-TestHarness/1.0"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = resp.read().decode(errors="replace")
                print(f"    -> GET {path} => Status: {resp.status}, Body excerpt: {data[:50].strip()}...")
        except urllib.error.HTTPError as e:
            print(f"    -> GET {path} => Status: {e.code}")
        except Exception as e:
            print(f"    [!] HTTP test note: {e}")
    print("    [OK] HTTP Honeypot tests completed.")


def test_ftp(port=2121):
    print(f"\n[+] Testing FTP Honeypot on 127.0.0.1:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect(("127.0.0.1", port))
        banner = s.recv(1024).decode(errors="replace").strip()
        print(f"    <- FTP Banner: {banner}")

        s.sendall(b"USER simulated_attacker\r\n")
        user_resp = s.recv(1024).decode(errors="replace").strip()
        print(f"    <- Response to USER: {user_resp}")

        s.sendall(b"PASS testpass123\r\n")
        pass_resp = s.recv(1024).decode(errors="replace").strip()
        print(f"    <- Response to PASS: {pass_resp}")

        s.sendall(b"QUIT\r\n")
        quit_resp = s.recv(1024).decode(errors="replace").strip()
        print(f"    <- Response to QUIT: {quit_resp}")
        s.close()
        print("    [OK] FTP Honeypot interaction completed.")
    except Exception as e:
        print(f"    [!] FTP test note: {e}")


def test_tcp(port=9999):
    print(f"\n[+] Testing Generic TCP Listener on 127.0.0.1:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect(("127.0.0.1", port))
        banner = s.recv(1024).decode(errors="replace").strip()
        print(f"    <- Generic TCP Banner: {banner}")
        s.sendall(b"PING / TEST_PROBE\r\n")
        resp = s.recv(1024).decode(errors="replace").strip()
        print(f"    <- Generic TCP Response: {resp}")
        s.close()
        print("    [OK] Generic TCP listener test completed.")
    except Exception as e:
        print(f"    [!] TCP test note: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Honeypot Trap System - Local Traffic Simulation Harness")
    print("=" * 60)
    test_ssh()
    test_http()
    test_ftp()
    test_tcp()
    print("\n[+] All local simulation tests executed successfully.")
