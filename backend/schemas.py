"""Pydantic schemas for FastAPI endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from src.models.alert import (
    AlertStatus,
    InvestigationReport,
    InvestigationResult,
    RecommendedAction,
    Severity,
    Verdict,
)


class AlertCreate(BaseModel):
    id: str
    timestamp: datetime
    source: str
    title: str
    description: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    scenario_id: str = ""


class AlertSummary(BaseModel):
    id: str
    timestamp: datetime
    source: str
    title: str
    description: str
    status: AlertStatus
    severity: Severity | None = None
    scenario_id: str = ""
    verdict: Verdict | None = None
    recommended_action: RecommendedAction | None = None
    severity_score: float | None = None


class AlertDetail(AlertSummary):
    raw_data: dict[str, Any]
    investigation: InvestigationResult | None = None
    has_report: bool = False


class StatsResponse(BaseModel):
    total_alerts: int
    pending_alerts: int
    completed_alerts: int
    critical_alerts: int
    medium_alerts: int
    low_alerts: int
    true_positives: int
    false_positives: int
    suspicious: int


class InvestigateResponse(BaseModel):
    alert_id: str
    status: str
    verdict: str
    recommended_action: str
    severity: str
    severity_score: float
    steps_count: int
    completed_at: datetime
