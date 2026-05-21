from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime, date

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.alert import Alert
from app.models.user import User
from app.schemas.schemas import AlertIn, TriageResult, AlertUpdate, DashboardStats
from app.services.triage_engine import triage
from app.services.enrichment import enrich_ip

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.post("/triage", response_model=TriageResult, status_code=201)
async def triage_alert(
    alert_in: AlertIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Core endpoint: Submit a raw SIEM/EDR event for automated triage.
    
    Pipeline:
      1. Enrich source IP via AbuseIPDB
      2. Score risk + map to MITRE ATT&CK
      3. Generate response recommendation
      4. Persist to database
    """
    enrichment = await enrich_ip(alert_in.source_ip)
    decision = triage(
        event_type=alert_in.event_type,
        log_message=alert_in.log_message,
        ip_abuse_score=enrichment["abuse_score"],
    )

    alert = Alert(
        source_ip=alert_in.source_ip,
        event_type=alert_in.event_type,
        log_message=alert_in.log_message,
        tool=alert_in.tool,
        severity=decision.severity,
        risk_score=decision.risk_score,
        mitre_technique=decision.mitre_technique,
        mitre_tactic=decision.mitre_tactic,
        recommended_action=decision.recommended_action,
        ip_abuse_score=enrichment["abuse_score"],
        ip_country=enrichment["country"],
        ip_is_tor=enrichment["is_tor"],
        owner_id=current_user.id,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/", response_model=List[TriageResult])
async def list_alerts(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List alerts with optional filters. Supports pagination."""
    q = select(Alert).order_by(Alert.created_at.desc())
    if severity:
        q = q.where(Alert.severity == severity)
    if status:
        q = q.where(Alert.status == status)
    if event_type:
        q = q.where(Alert.event_type == event_type)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/dashboard", response_model=DashboardStats)
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Aggregated stats for the SOC dashboard."""
    total = (await db.execute(select(func.count(Alert.id)))).scalar()
    open_count = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "open")
    )).scalar()
    critical = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == "critical")
    )).scalar()
    high = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == "high")
    )).scalar()

    today_start = datetime.combine(date.today(), datetime.min.time())
    resolved_today = (await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.status == "resolved", Alert.updated_at >= today_start)
        )
    )).scalar()

    # Top 5 event types
    top_events_q = (
        select(Alert.event_type, func.count(Alert.id).label("cnt"))
        .group_by(Alert.event_type)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    )
    top_events = [(r.event_type, r.cnt) for r in (await db.execute(top_events_q)).all()]

    # Severity breakdown
    sev_q = select(Alert.severity, func.count(Alert.id).label("cnt")).group_by(Alert.severity)
    sev_breakdown = {r.severity: r.cnt for r in (await db.execute(sev_q)).all()}

    return DashboardStats(
        total_alerts=total,
        open_alerts=open_count,
        critical_alerts=critical,
        high_alerts=high,
        resolved_today=resolved_today,
        top_event_types=top_events,
        severity_breakdown=sev_breakdown,
    )


@router.get("/{alert_id}", response_model=TriageResult)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=TriageResult)
async def update_alert(
    alert_id: int,
    update: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update alert status and analyst notes — supports analyst workflow."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update.status:
        alert.status = update.status
    if update.analyst_notes is not None:
        alert.analyst_notes = update.analyst_notes
    alert.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(alert)
    return alert
