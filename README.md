# 🛡️ CyberTriage API

> An automated security alert triage platform built with FastAPI — mirroring the core pipeline of Managed Detection & Response (MDR) products.

---

## What This Is

Modern MDR platforms like Critical Start ingest thousands of security alerts daily from SIEMs (Splunk, QRadar) and EDR tools (CrowdStrike, SentinelOne). A human analyst cannot triage them all manually. **CyberTriage** automates this pipeline:

```
Raw SIEM/EDR Event
       ↓
  IP Enrichment         ← AbuseIPDB threat intel
       ↓
  Risk Scoring          ← Event type + keyword analysis + IP abuse score
       ↓
  MITRE ATT&CK Mapping  ← Industry-standard technique classification
       ↓
  Response Decision     ← Isolate / Block / Investigate / Monitor
       ↓
  Analyst Dashboard     ← Live alert queue with status tracking
```

---

## Features

| Feature | Details |
|---|---|
| **JWT Authentication** | Secure analyst login / registration |
| **Automated Triage** | 12 event types, risk score 0–100 |
| **MITRE ATT&CK** | Maps every alert to a technique + tactic |
| **AbuseIPDB Integration** | Real-time IP threat intelligence |
| **Analyst Workflow** | Status tracking: open → investigating → resolved |
| **SOC Dashboard UI** | Live alert queue, filters, stats |
| **PostgreSQL Ready** | Swap `DATABASE_URL` env var — zero code changes |
| **Dockerized** | One command to run the full stack |
| **22 Tests** | Engine unit tests + full API integration tests |

---

## Tech Stack

- **Python 3.12** + **FastAPI** — async REST API
- **SQLAlchemy 2.0 async** — ORM with async session management
- **Pydantic v2** — request/response validation
- **JWT (python-jose)** — stateless authentication
- **AbuseIPDB API** — IP reputation enrichment
- **SQLite** (dev) / **PostgreSQL** (prod via Docker)
- **pytest + httpx** — async integration tests

---

## Quick Start

### Option 1 — Local (SQLite, no Docker)

```bash
# Clone
git clone https://github.com/YOURUSERNAME/cybertriage.git
cd cybertriage

# Install dependencies
pip install -r requirements.txt

# Run
uvicorn main:app --reload

# Open http://localhost:8000
```

### Option 2 — Docker Compose (PostgreSQL)

```bash
docker-compose up --build
# Open http://localhost:8000
```

---

## Using the SOC Dashboard

1. Open `http://localhost:8000`
2. Register an analyst account
3. Go to **⚡ Submit Alert** tab and try:

```json
{
  "source_ip": "185.220.101.45",
  "event_type": "brute_force",
  "log_message": "47 failed SSH login attempts for root — threshold exceeded",
  "tool": "splunk"
}
```

You'll get back:
- **Severity**: critical
- **Risk Score**: 100.0 / 100
- **MITRE**: T1110 – Brute Force (Credential Access)
- **IP**: Known Threat Actor, AbuseScore: 95%
- **Action**: 🔴 IMMEDIATE: Isolate host, block IP at firewall, page on-call analyst

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Create analyst account |
| `POST` | `/api/auth/login` | Get JWT token |
| `POST` | `/api/alerts/triage` | Submit alert for triage |
| `GET` | `/api/alerts/` | List alerts (filter by severity, status) |
| `GET` | `/api/alerts/dashboard` | Aggregated SOC stats |
| `GET` | `/api/alerts/{id}` | Get specific alert |
| `PATCH` | `/api/alerts/{id}` | Update status / analyst notes |
| `GET` | `/health` | Health check |
| `GET` | `/docs` | Interactive Swagger docs |

---

## MITRE ATT&CK Coverage

| Event Type | Technique | Tactic |
|---|---|---|
| brute_force | T1110 – Brute Force | Credential Access |
| sql_injection | T1190 – Exploit Public-Facing App | Initial Access |
| privilege_escalation | T1068 – Exploitation for Priv Esc | Privilege Escalation |
| lateral_movement | T1021 – Remote Services | Lateral Movement |
| data_exfiltration | T1041 – Exfiltration Over C2 | Exfiltration |
| ransomware | T1486 – Data Encrypted for Impact | Impact |
| c2_beacon | T1071 – App Layer Protocol | Command & Control |
| ... | ... | ... |

---

## Risk Scoring Algorithm

```python
risk_score = base_score          # from event type (40–98)
           + keyword_boost        # log message analysis (max +25)
           + ip_boost             # AbuseIPDB score (max +15)

# Clamped to 0–100
# Severity: critical ≥90 | high ≥70 | medium ≥45 | low <45
```

---

## Running Tests

```bash
pytest tests/ -v --asyncio-mode=auto
# 22 passed
```

---

## Project Structure

```
cybertriage/
├── main.py                    # FastAPI app + lifespan
├── app/
│   ├── api/
│   │   ├── auth.py            # Register + Login endpoints
│   │   └── alerts.py          # Triage + CRUD + Dashboard endpoints
│   ├── core/
│   │   ├── config.py          # Settings (env-based)
│   │   ├── database.py        # Async SQLAlchemy engine
│   │   └── security.py        # JWT utilities + auth dependency
│   ├── models/
│   │   ├── user.py            # User ORM model
│   │   └── alert.py           # Alert ORM model
│   ├── schemas/
│   │   └── schemas.py         # Pydantic request/response models
│   ├── services/
│   │   ├── triage_engine.py   # Core risk scoring + MITRE mapping
│   │   └── enrichment.py      # AbuseIPDB IP enrichment
│   └── static/
│       └── dashboard.html     # SOC dashboard UI
├── tests/
│   └── test_api.py            # 22 tests (engine + auth + alerts)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | SQLite | Swap to PostgreSQL for production |
| `SECRET_KEY` | (set this!) | JWT signing key |
| `ABUSEIPDB_API_KEY` | None | Optional — enables live IP enrichment |

---

## Built by

[Your Name] — [Your GitHub] — [Your LinkedIn]
