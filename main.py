from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import os

from app.core.config import settings
from app.core.database import init_db
from app.api import auth, alerts


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="""
## CyberTriage API 🛡️

An automated security alert triage platform that mirrors the core pipeline of 
**Managed Detection & Response (MDR)** products like Critical Start.

### Pipeline
`Raw SIEM/EDR Event` → `IP Enrichment (AbuseIPDB)` → `Risk Scoring` → `MITRE ATT&CK Mapping` → `Response Recommendation`

### Features
- **JWT Authentication** — secure analyst access
- **Automated Triage** — risk scoring across 12 event types
- **MITRE ATT&CK Mapping** — industry-standard technique classification
- **AbuseIPDB Integration** — real-time IP threat intelligence
- **Analyst Workflow** — status tracking, notes, filtering
- **SOC Dashboard** — live alert queue with filtering and stats
- **PostgreSQL Ready** — swap DATABASE_URL env var, zero code changes
    """,
    lifespan=lifespan,
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "app", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Routers
app.include_router(auth.router)
app.include_router(alerts.router)


@app.get("/", include_in_schema=False)
async def root():
    """Serve the SOC dashboard UI."""
    dashboard_path = os.path.join(static_dir, "dashboard.html")
    return FileResponse(dashboard_path)


@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": settings.VERSION, "app": settings.APP_NAME}
