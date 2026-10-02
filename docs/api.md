# Honeypot Trap System - REST API & WebSocket Documentation

The backend exposes a secure REST API and WebSocket real-time feed powered by FastAPI.
All administrative endpoints require a valid JWT Bearer token in the `Authorization` header:
```http
Authorization: Bearer <access_token>
```

Interactive OpenAPI Swagger documentation is available at `http://localhost:8000/docs`.

---

## 1. Authentication Endpoints

### `POST /api/auth/login`
Authenticates operator and issues a signed JWT token. Accepts both `application/x-www-form-urlencoded` and `application/json`.

**Request Body (JSON):**
```json
{
  "username": "admin",
  "password": "adminpassword123"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
  "token_type": "bearer",
  "username": "admin",
  "role": "admin"
}
```

### `GET /api/auth/me`
Retrieves profile of the currently authenticated operator.

---

## 2. Dashboard Analytics

### `GET /api/dashboard/summary`
Calculates and returns aggregated Security Operations Center (SOC) telemetry metrics.

**Response (200 OK):**
```json
{
  "total_events": 1420,
  "events_last_24h": 320,
  "unique_ips": 45,
  "high_critical_events": 88,
  "active_services": 4,
  "total_alerts": 12,
  "severity_distribution": [
    { "name": "LOW", "value": 850 },
    { "name": "MEDIUM", "value": 482 },
    { "name": "HIGH", "value": 76 },
    { "name": "CRITICAL", "value": 12 }
  ],
  "event_type_distribution": [
    { "name": "CONNECTION", "value": 600 },
    { "name": "HTTP_REQUEST", "value": 420 },
    { "name": "FAILED_LOGIN", "value": 210 },
    { "name": "SUSPICIOUS_REQUEST", "value": 110 },
    { "name": "PORT_SCAN", "value": 80 }
  ],
  "timeline_24h": [
    { "timestamp": "04:00", "count": 45, "high_count": 5 },
    { "timestamp": "08:00", "count": 78, "high_count": 12 }
  ],
  "top_services": [
    { "service": "HTTP Honeypot", "count": 530, "percentage": 37.3 },
    { "service": "SSH Honeypot", "count": 420, "percentage": 29.5 }
  ],
  "top_source_ips": [
    {
      "ip": "192.168.1.105",
      "count": 142,
      "highest_severity": "CRITICAL",
      "highest_score": 100,
      "services": ["HTTP Honeypot", "SSH Honeypot"]
    }
  ],
  "recent_events": [],
  "recent_alerts": []
}
```

---

## 3. Events Telemetry

### `GET /api/events`
Returns paginated, searchable, and filtered telemetry logs.

**Query Parameters:**
- `page` (int, default: 1): Page number (>= 1)
- `page_size` (int, default: 20): Items per page (1 – 100)
- `search` (str, optional): Search string across IP, service, event type, or payload
- `severity` (str, optional): Filter by `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `service` (str, optional): Filter by service name
- `source_ip` (str, optional): Filter by source IP

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": 1,
      "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "timestamp": "2026-09-29T21:45:00Z",
      "source_ip": "10.0.0.54",
      "source_port": 50221,
      "destination_port": 2222,
      "protocol": "TCP",
      "service": "SSH Honeypot",
      "event_type": "FAILED_LOGIN",
      "severity": "HIGH",
      "risk_score": 75,
      "session_id": "sess-uuid",
      "metadata_json": "{\"attempted_user\":\"root\"}",
      "raw_payload": "Authentication probe for user 'root'",
      "created_at": "2026-09-29T21:45:00Z"
    }
  ],
  "total": 1420,
  "page": 1,
  "page_size": 20,
  "total_pages": 71
}
```

### `GET /api/events/{event_id}`
Returns granular telemetry details for an event including triggered detection rules and scoring breakdown.

---

## 4. Honeypot Service Management

### `GET /api/honeypots`
Lists all honeypots, assigned ports, and runtime operational statuses.

### `POST /api/honeypots/{service_id}/start`
Starts a honeypot listener socket. Requires admin privilege.

### `POST /api/honeypots/{service_id}/stop`
Stops a honeypot listener socket. Requires admin privilege.

---

## 5. Security Incident Alerts

### `GET /api/alerts`
Retrieves incident alerts filtered by status (`NEW`, `ACKNOWLEDGED`, `RESOLVED`) or severity.

### `PATCH /api/alerts/{alert_id}`
Updates alert status and adds operator triage notes.

**Request Body:**
```json
{
  "status": "ACKNOWLEDGED",
  "notes": "Correlating with firewall drop logs."
}
```

---

## 6. Threat Intelligence Reports & Data Export

### `GET /api/reports/summary`
Generates an executive threat intelligence summary report for `daily`, `weekly`, or `custom` time ranges.

### `GET /api/reports/export/csv`
Streams telemetry logs formatted as downloadable CSV spreadsheet.

### `GET /api/reports/export/json`
Exports telemetry logs as structured JSON.

---

## 7. Detection Rules & Risk Settings

### `GET /api/settings`
Returns detection rules list, rule activation flags, and risk scoring weights.

### `PUT /api/settings/rules/{rule_id}`
Enables or disables an individual detection rule.

### `PUT /api/settings/weights`
Updates heuristic risk scoring factor weights.

---

## 8. Real-Time WebSocket Telemetry Feed

### `WS /ws/events`
Connects to real-time event streaming pipeline.

**Message Format (Event Broadcast):**
```json
{
  "type": "NEW_EVENT",
  "data": {
    "event_id": "...",
    "timestamp": "2026-09-29T21:50:00Z",
    "source_ip": "192.168.1.105",
    "service": "HTTP Honeypot",
    "severity": "CRITICAL",
    "risk_score": 95,
    "detections_count": 3,
    "has_alert": true
  }
}
```

**Message Format (Alert Broadcast):**
```json
{
  "type": "NEW_ALERT",
  "data": {
    "alert_id": "...",
    "title": "CRITICAL Security Event on HTTP Honeypot from 192.168.1.105",
    "severity": "CRITICAL",
    "source_ip": "192.168.1.105",
    "status": "NEW"
  }
}
```
