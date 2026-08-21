"""Unit tests for the investigation report generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.data.log_store import LogStore
from src.models.alert import Alert
from src.reporting.report_generator import ReportGenerator


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture
def log_store(project_root: Path) -> LogStore:
    return LogStore(project_root / "data" / "scenarios")


@pytest.fixture
def agent(log_store: LogStore, project_root: Path) -> SentinelInvestigationAgent:
    return SentinelInvestigationAgent(
        log_store=log_store,
        threat_intel_path=project_root / "data" / "threat_intel" / "known_iocs.json",
        use_llm=False,
    )


@pytest.fixture
def sample_alerts(project_root: Path) -> list[Alert]:
    alerts_file = project_root / "data" / "alerts" / "sample_alerts.json"
    with alerts_file.open("r", encoding="utf-8") as fh:
        raw_list = json.load(fh)
    return [Alert.model_validate(a) for a in raw_list]


@pytest.fixture
def report_generator() -> ReportGenerator:
    return ReportGenerator()


class TestReportGenerator:
    def test_generate_report_structure(
        self,
        agent: SentinelInvestigationAgent,
        sample_alerts: list[Alert],
        report_generator: ReportGenerator,
    ) -> None:
        """Report contains all required fields."""
        alert = sample_alerts[0]
        result = agent.investigate(alert)
        report = report_generator.generate(alert=alert, result=result)

        assert report.alert_id == alert.id
        assert report.title
        assert report.executive_summary
        assert report.markdown
        assert report.verdict in ("true_positive", "false_positive", "suspicious")
        assert report.recommended_action in ("contain", "escalate", "monitor", "ignore")
        assert report.generated_at is not None

    def test_report_markdown_contains_key_sections(
        self,
        agent: SentinelInvestigationAgent,
        sample_alerts: list[Alert],
        report_generator: ReportGenerator,
    ) -> None:
        """Markdown output has all required sections."""
        alert = sample_alerts[0]
        result = agent.investigate(alert)
        report = report_generator.generate(alert=alert, result=result)

        assert "Résumé Exécutif" in report.markdown
        assert "IOCs Extraits" in report.markdown
        assert "Chronologie des Événements" in report.markdown
        assert "Corrélation des Preuves" in report.markdown
        assert "Threat Intel" in report.markdown
        assert "Scoring de Sévérité" in report.markdown
        assert "Recommandation" in report.markdown
        assert "Raisonnement de l'Agent" in report.markdown
        assert alert.id in report.markdown

    def test_report_true_positive_contains_action_items(
        self,
        agent: SentinelInvestigationAgent,
        sample_alerts: list[Alert],
        report_generator: ReportGenerator,
    ) -> None:
        """True positive report includes containment action items."""
        alert = sample_alerts[0]  # Web defacement → true positive
        result = agent.investigate(alert)
        report = report_generator.generate(alert=alert, result=result)

        assert report.verdict == "true_positive"
        assert len(report.action_items) >= 3  # Multiple containment actions

    def test_report_false_positive_summary(
        self,
        agent: SentinelInvestigationAgent,
        sample_alerts: list[Alert],
        report_generator: ReportGenerator,
    ) -> None:
        """False positive report summary indicates benign activity."""
        alert = next(a for a in sample_alerts if a.id == "ALT-2024-006")
        result = agent.investigate(alert)
        report = report_generator.generate(alert=alert, result=result)

        assert report.verdict == "false_positive"
        assert "faux positif" in report.executive_summary.lower()

    def test_report_serializable_to_json(
        self,
        agent: SentinelInvestigationAgent,
        sample_alerts: list[Alert],
        report_generator: ReportGenerator,
    ) -> None:
        """Report model can be serialized to JSON."""
        alert = sample_alerts[0]
        result = agent.investigate(alert)
        report = report_generator.generate(alert=alert, result=result)

        json_str = report.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["alert_id"] == alert.id
        assert parsed["markdown"]
