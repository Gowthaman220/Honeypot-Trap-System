# Honeypot Trap System - Deployment & Operations Guide

## 1. Quick Start with Docker Compose

The primary deployment method uses Docker Compose to orchestrate the backend and frontend containers on an isolated bridge network.

```bash
docker compose up --build
```

### Services & Port Allocation

| Container | Host Port | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| `honeypot_frontend` | `3000` | HTTP | React SOC Monitoring Dashboard |
| `honeypot_backend` | `8000` | HTTP/WS | Administrative REST API & WebSocket Stream |
| `honeypot_backend` | `2222` | TCP | Controlled Safe SSH Honeypot Listener |
| `honeypot_backend` | `8080` | TCP | Controlled Safe HTTP Honeypot Listener |
| `honeypot_backend` | `2121` | TCP | Controlled Safe FTP Honeypot Listener |
| `honeypot_backend` | `9999` | TCP | Controlled Safe Generic TCP Listener |

---

## 2. Environment Configuration Reference

Configure deployment variables in `.env` (or via container environment overrides):

```env
# Application Settings
APP_NAME="Honeypot Trap System"
ENVIRONMENT="production"
DEBUG=false
SECRET_KEY="replace-with-a-random-32-byte-hex-string"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Database Connection (Default: SQLite for local deployment)
DATABASE_URL="sqlite:////app/data/honeypot.db"
# Or PostgreSQL:
# DATABASE_URL="postgresql://user:password@postgres:5432/honeypot_db"

# Admin Initial Account
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="adminpassword123"

# Controlled Honeypot Ports
SSH_HONEYPOT_ENABLED=true
SSH_HONEYPOT_PORT=2222

HTTP_HONEYPOT_ENABLED=true
HTTP_HONEYPOT_PORT=8080

FTP_HONEYPOT_ENABLED=true
FTP_HONEYPOT_PORT=2121

TCP_HONEYPOT_ENABLED=true
TCP_HONEYPOT_PORT=9999

# Allowed CORS Origins
CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]

# Optional Notification Dispatch
ALERT_EMAIL_ENABLED=false
ALERT_WEBHOOK_ENABLED=false
ALERT_WEBHOOK_URL=""
```

---

## 3. Local Bare-Metal Execution (Development Mode)

If Docker is not installed on the host, run the components natively:

### Backend:
```bash
# 1. Install dependencies
cd backend
pip install -r requirements.txt

# 2. Initialize database
python -m app.core.init_db

# 3. Launch backend and honeypots
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend:
```bash
# 1. Install dependencies
cd frontend
npm install

# 2. Launch Vite dev server
npm run dev
```

Access the dashboard at `http://localhost:5173` with credentials `admin` / `adminpassword123`.

---

## 4. Privacy & Data Handling Policy

The Honeypot Trap System implements defensive privacy safeguards:
1. **Minimization**: Only connection metadata (timestamp, source IP, source port, target service, protocol, and payload snippet) is captured.
2. **No PII Collection**: No personal identity attributes, email addresses, or real passwords are harvested.
3. **Security Telemetry Classification**: Source IP addresses are stored strictly as defensive security telemetry indicators.
4. **Data Retention**: Old events can be purged or rotated through standard database administrative queries.
