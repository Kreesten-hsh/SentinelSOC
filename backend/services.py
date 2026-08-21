"""Backend service layer for SentinelSOC.

Handles:
- Initial database seeding from sample_alerts.json
- Agent execution and database synchronization
- Report generation and caching
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database import AlertRecord, InvestigationRecord, ReportRecord
from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.data.log_store import LogStore
from src.models.alert import (
    Alert,
    AlertStatus,
    InvestigationReport,
    InvestigationResult,
    Severity,
)
from src.reporting.report_generator import ReportGenerator

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class SentinelService:
    def __init__(self) -> None:
        self.log_store = LogStore(PROJECT_ROOT / "data" / "scenarios")
        self.agent = SentinelInvestigationAgent(
            log_store=self.log_store,
            threat_intel_path=PROJECT_ROOT / "data" / "threat_intel" / "known_iocs.json",
            use_llm=False,
        )
        self.report_gen = ReportGenerator()

    async def seed_alerts(self, session: AsyncSession, force_reload: bool = False) -> int:
        """Seed initial 8 alerts from sample_alerts.json if table is empty or forced."""
        result = await session.execute(select(AlertRecord))
        existing = result.scalars().all()
        if existing and not force_reload:
            return len(existing)

        if force_reload:
            await session.execute(delete(ReportRecord))
            await session.execute(delete(InvestigationRecord))
            await session.execute(delete(AlertRecord))
            await session.commit()

        alerts_file = PROJECT_ROOT / "data" / "alerts" / "sample_alerts.json"
        if not alerts_file.is_file():
            return 0

        with alerts_file.open("r", encoding="utf-8") as fh:
            raw_list = json.load(fh)

        count = 0
        for raw in raw_list:
            alert = Alert.model_validate(raw)
            rec = AlertRecord(
                id=alert.id,
                timestamp=alert.timestamp,
                source=alert.source,
                title=alert.title,
                description=alert.description,
                raw_data=alert.raw_data,
                status=alert.status.value,
                severity=alert.severity.value if alert.severity else None,
                scenario_id=alert.scenario_id,
            )
            session.add(rec)
            count += 1

        await session.commit()
        return count

    async def run_investigation_for_alert(
        self, session: AsyncSession, alert_id: str
    ) -> tuple[InvestigationResult, InvestigationReport]:
        """Run full autonomous agent investigation on an alert and persist results."""
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.id == alert_id)
            .options(
                selectinload(AlertRecord.investigation),
                selectinload(AlertRecord.report),
            )
        )
        res = await session.execute(stmt)
        alert_rec = res.scalar_one_or_none()
        if not alert_rec:
            raise ValueError(f"Alert with id {alert_id} not found")

        # Convert record to Alert model
        alert_model = Alert(
            id=alert_rec.id,
            timestamp=alert_rec.timestamp,
            source=alert_rec.source,
            title=alert_rec.title,
            description=alert_rec.description,
            raw_data=alert_rec.raw_data,
            status=AlertStatus(alert_rec.status),
            severity=Severity(alert_rec.severity) if alert_rec.severity else None,
            scenario_id=alert_rec.scenario_id,
        )

        # Execute investigation
        inv_result = self.agent.investigate(alert_model)

        # Generate report
        report_model = self.report_gen.generate(alert=alert_model, result=inv_result)

        # Update alert status & severity
        alert_rec.status = AlertStatus.COMPLETED.value
        if inv_result.severity_score:
            alert_rec.severity = inv_result.severity_score.severity.value

        # Persist investigation record
        inv_dict = json.loads(inv_result.model_dump_json())
        if alert_rec.investigation:
            alert_rec.investigation.verdict = inv_result.verdict.value if inv_result.verdict else None
            alert_rec.investigation.recommended_action = inv_result.recommended_action.value if inv_result.recommended_action else None
            alert_rec.investigation.severity_score = inv_result.severity_score.final_score if inv_result.severity_score else None
            alert_rec.investigation.severity_level = inv_result.severity_score.severity.value if inv_result.severity_score else None
            alert_rec.investigation.steps_count = len(inv_result.steps)
            alert_rec.investigation.data = inv_dict
            alert_rec.investigation.completed_at = inv_result.completed_at
        else:
            inv_rec = InvestigationRecord(
                alert_id=alert_id,
                verdict=inv_result.verdict.value if inv_result.verdict else None,
                recommended_action=inv_result.recommended_action.value if inv_result.recommended_action else None,
                severity_score=inv_result.severity_score.final_score if inv_result.severity_score else None,
                severity_level=inv_result.severity_score.severity.value if inv_result.severity_score else None,
                steps_count=len(inv_result.steps),
                data=inv_dict,
                started_at=inv_result.started_at,
                completed_at=inv_result.completed_at,
            )
            session.add(inv_rec)

        # Persist report record
        report_dict = json.loads(report_model.model_dump_json())
        if alert_rec.report:
            alert_rec.report.title = report_model.title
            alert_rec.report.executive_summary = report_model.executive_summary
            alert_rec.report.markdown = report_model.markdown
            alert_rec.report.data = report_dict
            alert_rec.report.generated_at = report_model.generated_at
        else:
            rep_rec = ReportRecord(
                alert_id=alert_id,
                title=report_model.title,
                executive_summary=report_model.executive_summary,
                markdown=report_model.markdown,
                data=report_dict,
                generated_at=report_model.generated_at,
            )
            session.add(rep_rec)

        await session.commit()
        return inv_result, report_model


# Singleton service instance
sentinel_service = SentinelService()
