# Honeypot Trap System - Testing & Verification Guide

## 1. Testing Philosophy & Scope

All test routines adhere to defensive security verification guidelines:
- Tests target exclusively local, in-memory, or localhost (`127.0.0.1`) test targets.
- No network requests are made to external internet hosts.
- Synthetic datasets use private RFC-1918 test subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

---

## 2. Test Suite Architecture

The automated test suite is built on `pytest` and structured into 7 modular test modules:

| Test Module | Component Tested | Coverage |
| :--- | :--- | :--- |
| `tests/test_auth.py` | Password hashing & JWT Tokens | Bcrypt salt hashing, token generation, decoding, protected routes |
| `tests/test_events.py` | Ingestion & Pagination | Normalization, database persistence, query filters, search |
| `tests/test_detection_engine.py` | Threat Detection Rules | Rules R001 to R007 triggers, false positive avoidance |
| `tests/test_risk_scorer.py` | Heuristic Risk Scoring | Mathematical weightings, score clamping (0-100), explainable factors |
| `tests/test_honeypot_services.py` | Socket Listeners | Asynchronous socket binding, banner issuance, shutdown cleanup |
| `tests/test_alerts.py` | Security Alerts Lifecycle | Alert generation on high/critical events, triage state transitions |
| `tests/test_security.py` | Security Hardening | SQL injection resistance, query parameter validation, unauthorized access |

---

## 3. Running Automated Tests

Run the full pytest suite from the `backend/` directory:
```bash
cd backend
pytest -v
```

Expected output:
```text
tests/test_alerts.py::test_alert_generation_on_critical_event PASSED
tests/test_alerts.py::test_alert_lifecycle_api PASSED
tests/test_auth.py::test_password_hashing PASSED
tests/test_auth.py::test_jwt_token_lifecycle PASSED
tests/test_auth.py::test_login_success PASSED
tests/test_auth.py::test_login_invalid_credentials PASSED
tests/test_auth.py::test_protected_route_unauthorized PASSED
tests/test_auth.py::test_protected_route_authorized PASSED
tests/test_detection_engine.py::test_suspicious_http_detection_r005 PASSED
tests/test_detection_engine.py::test_command_pattern_detection_r006 PASSED
tests/test_detection_engine.py::test_repeated_failed_auth_r002 PASSED
tests/test_detection_engine.py::test_port_scan_detection_r007 PASSED
tests/test_events.py::test_event_processing_and_persistence PASSED
tests/test_events.py::test_events_api_pagination_and_filtering PASSED
tests/test_events.py::test_event_detail_api PASSED
tests/test_honeypot_services.py::test_honeypot_startup_and_shutdown PASSED
tests/test_risk_scorer.py::test_baseline_risk_calculation PASSED
tests/test_risk_scorer.py::test_elevated_risk_with_detections PASSED
tests/test_risk_scorer.py::test_score_clamping PASSED
tests/test_security.py::test_sql_injection_resistant_queries PASSED
tests/test_security.py::test_input_validation_on_event_query PASSED
tests/test_security.py::test_unauthenticated_security_barrier PASSED
======================== 22 passed in 5.90s ========================
```

---

## 4. Live Socket Traffic Simulation

When the backend application is running, execute the safe traffic simulator to test real socket communication across all honeypot listeners:

```bash
python scripts/simulate_traffic.py
```

This harness executes:
1. **SSH Connection (`127.0.0.1:2222`)**: Connects to the socket, reads the OpenSSH banner, submits simulated client identity, receives disconnect packet.
2. **HTTP Probes (`127.0.0.1:8080`)**: Sends HTTP GET requests to `/`, `/wp-login.php`, `/.env`, and `/phpmyadmin`. Verifies simulated server response and status 200 OK.
3. **FTP Interaction (`127.0.0.1:2121`)**: Interacts via `USER simulated_attacker`, `PASS testpass123`, and `QUIT`. Verifies rejection response `530 Login incorrect`.
4. **Generic TCP Probe (`127.0.0.1:9999`)**: Connects and queries the listener with a probe string; receives `Command not recognized` and disconnects.

---

## 5. Synthetic Dataset Generation

To populate the database with realistic attack scenarios for demonstration:
```bash
python scripts/generate_demo_data.py 120
```
This generates:
- Web directory scans and admin probes
- SSH brute force campaigns
- Port scanning reconnaissance
- Command injection vectors
- Multi-service targeting sequences
- Automated security alerts and IP profile records
