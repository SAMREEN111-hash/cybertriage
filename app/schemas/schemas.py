from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


# ── Auth ──────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str


# ── Alerts ────────────────────────────────────────────────────────────────────

class AlertIn(BaseModel):
    source_ip: str
    event_type: str
    log_message: str
    tool: str = "splunk"


class TriageResult(BaseModel):
    id: int
    source_ip: str
    event_type: str
    log_message: str
    tool: str
    severity: str
    risk_score: float
    mitre_technique: str
    mitre_tactic: str
    recommended_action: str
    ip_abuse_score: Optional[float] = None
    ip_country: Optional[str] = None
    ip_is_tor: Optional[str] = None
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = None


class DashboardStats(BaseModel):
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    resolved_today: int
    top_event_types: list
    severity_breakdown: dict
