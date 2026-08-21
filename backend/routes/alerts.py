"""Alerts and investigation endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database import AlertRecord, InvestigationRecord, ReportRecord, get_db
from backend.schemas import (
    AlertCreate,
    AlertDetail,
    AlertSummary,
    InvestigateResponse,
    StatsResponse,
)
from backend.services import sentinel_service
from src.models.alert import (
    AlertStatus,
    InvestigationReport,
    InvestigationResult,
    RecommendedAction,
    Severity,
    Verdict,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertSummary])
async def list_alerts(
    severity: str | None = Query(None, description="Filter by severity (critical, medium, low)"),
    status: str | None = Query(None, description="Filter by status (pending, completed, etc.)"),
    session: AsyncSession = Depends(get_db),
) -> list[AlertSummary]:
    """List all alerts with optional filtering, including investigation summary if completed."""
    stmt = select(AlertRecord).options(
        selectinload(AlertRecord.investigation),
    ).order_by(AlertRecord.timestamp.desc())

    if severity:
        stmt = stmt.where(AlertRecord.severity == severity.lower())
    if status:
        stmt = stmt.where(AlertRecord.status == status.lower())

    res = await session.execute(stmt)
    records = res.scalars().all()

    summaries: list[AlertSummary] = []
    for r in records:
        verdict = None
        action = None
        sev_score = None
        if r.investigation:
            verdict = Verdict(r.investigation.verdict) if r.investigation.verdict else None
            action = RecommendedAction(r.investigation.recommended_action) if r.investigation.recommended_action else None
            sev_score = r.investigation.severity_score

        summaries.append(
            AlertSummary(
                id=r.id,
                timestamp=r.timestamp,
                source=r.source,
                title=r.title,
                description=r.description,
                status=AlertStatus(r.status),
                severity=Severity(r.severity) if r.severity else None,
                scenario_id=r.scenario_id,
                verdict=verdict,
                recommended_action=action,
                severity_score=sev_score,
            )
        )
    return summaries


@router.get("/stats", response_model=StatsResponse)
async def get_stats(session: AsyncSession = Depends(get_db)) -> StatsResponse:
    """Get global alert counts, severity breakdown, and investigation verdicts."""
    alerts_res = await session.execute(
        select(AlertRecord).options(selectinload(AlertRecord.investigation))
    )
    records = alerts_res.scalars().all()

    total = len(records)
    pending = sum(1 for r in records if r.status == "pending")
    completed = sum(1 for r in records if r.status == "completed")
    critical = sum(1 for r in records if r.severity == "critical")
    medium = sum(1 for r in records if r.severity == "medium")
    low = sum(1 for r in records if r.severity == "low")

    tp = sum(1 for r in records if r.investigation and r.investigation.verdict == "true_positive")
    fp = sum(1 for r in records if r.investigation and r.investigation.verdict == "false_positive")
    susp = sum(1 for r in records if r.investigation and r.investigation.verdict == "suspicious")

    return StatsResponse(
        total_alerts=total,
        pending_alerts=pending,
        completed_alerts=completed,
        critical_alerts=critical,
        medium_alerts=medium,
        low_alerts=low,
        true_positives=tp,
        false_positives=fp,
        suspicious=susp,
    )


@router.post("/seed", response_model=dict[str, Any])
async def seed_or_reset_alerts(
    force: bool = Query(False, description="Force reset and re-seed 8 sample alerts"),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Seed or reset the 8 sample alerts and investigations from BOTS v1 dataset."""
    count = await sentinel_service.seed_alerts(session, force_reload=force)
    return {"status": "ok", "alerts_loaded": count}


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: str, session: AsyncSession = Depends(get_db)) -> AlertDetail:
    """Get full details of an alert, including full investigation trace if present."""
    stmt = (
        select(AlertRecord)
        .where(AlertRecord.id == alert_id)
        .options(
            selectinload(AlertRecord.investigation),
            selectinload(AlertRecord.report),
        )
    )
    res = await session.execute(stmt)
    r = res.scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    verdict = None
    action = None
    sev_score = None
    inv_data = None
    if r.investigation:
        verdict = Verdict(r.investigation.verdict) if r.investigation.verdict else None
        action = RecommendedAction(r.investigation.recommended_action) if r.investigation.recommended_action else None
        sev_score = r.investigation.severity_score
        if r.investigation.data:
            inv_data = InvestigationResult.model_validate(r.investigation.data)

    return AlertDetail(
        id=r.id,
        timestamp=r.timestamp,
        source=r.source,
        title=r.title,
        description=r.description,
        raw_data=r.raw_data or {},
        status=AlertStatus(r.status),
        severity=Severity(r.severity) if r.severity else None,
        scenario_id=r.scenario_id,
        verdict=verdict,
        recommended_action=action,
        severity_score=sev_score,
        investigation=inv_data,
        has_report=r.report is not None,
    )


@router.post("/{alert_id}/investigate", response_model=InvestigateResponse)
async def trigger_investigation(
    alert_id: str, session: AsyncSession = Depends(get_db)
) -> InvestigateResponse:
    """Trigger the autonomous agent investigation for an alert."""
    try:
        inv, report = await sentinel_service.run_investigation_for_alert(session, alert_id)
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err

    return InvestigateResponse(
        alert_id=alert_id,
        status="completed",
        verdict=inv.verdict.value if inv.verdict else "unknown",
        recommended_action=inv.recommended_action.value if inv.recommended_action else "unknown",
        severity=inv.severity_score.severity.value if inv.severity_score else "unknown",
        severity_score=inv.severity_score.final_score if inv.severity_score else 0.0,
        steps_count=len(inv.steps),
        completed_at=inv.completed_at or inv.started_at,
    )


@router.get("/{alert_id}/report", response_model=dict[str, Any])
async def get_alert_report(
    alert_id: str, session: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """Retrieve rendered Markdown report and structured summary."""
    stmt = select(ReportRecord).where(ReportRecord.alert_id == alert_id)
    res = await session.execute(stmt)
    rep = res.scalar_one_or_none()
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report for alert {alert_id} not found")

    return {
        "alert_id": rep.alert_id,
        "title": rep.title,
        "executive_summary": rep.executive_summary,
        "markdown": rep.markdown,
        "data": rep.data,
        "generated_at": rep.generated_at.isoformat(),
    }
