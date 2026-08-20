"""Unit tests for the SentinelInvestigationAgent across the 8 investigation scenarios."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.data.log_store import LogStore
from src.models.alert import Alert, RecommendedAction, Verdict


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture
def log_store(project_root: Path) -> LogStore:
    return LogStore(project_root / "data" / "scenarios")


@pytest.fixture
def sample_alerts(project_root: Path) -> list[Alert]:
    alerts_file = project_root / "data" / "alerts" / "sample_alerts.json"
    with alerts_file.open("r", encoding="utf-8") as fh:
        raw_list = json.load(fh)
    return [Alert.model_validate(a) for a in raw_list]


@pytest.fixture
def ground_truth(project_root: Path) -> dict:
    gt_file = project_root / "data" / "scenarios" / "ground_truth.json"
    with gt_file.open("r", encoding="utf-8") as fh:
        return json.load(fh)["scenarios"]


@pytest.fixture
def agent(log_store: LogStore, project_root: Path) -> SentinelInvestigationAgent:
    return SentinelInvestigationAgent(
        log_store=log_store,
        threat_intel_path=project_root / "data" / "threat_intel" / "known_iocs.json",
        use_llm=False,
    )


class TestSentinelInvestigationAgent:
    def test_agent_investigation_steps_structure(self, agent: SentinelInvestigationAgent, sample_alerts: list[Alert]) -> None:
        alert_01 = sample_alerts[0]
        result = agent.investigate(alert_01)

        assert result.alert_id == alert_01.id
        assert len(result.steps) == 6
        assert all(step.reasoning for step in result.steps)
        assert all(step.tool_used for step in result.steps)
        assert result.verdict == Verdict.TRUE_POSITIVE
        assert result.recommended_action == RecommendedAction.CONTAIN

    def test_agent_evaluates_false_positive(self, agent: SentinelInvestigationAgent, sample_alerts: list[Alert]) -> None:
        alert_06 = next(a for a in sample_alerts if a.id == "ALT-2024-006")
        result = agent.investigate(alert_06)

        assert result.verdict == Verdict.FALSE_POSITIVE
        assert result.recommended_action == RecommendedAction.IGNORE

    def test_agent_evaluates_ambiguous_lateral_movement(self, agent: SentinelInvestigationAgent, sample_alerts: list[Alert]) -> None:
        alert_07 = next(a for a in sample_alerts if a.id == "ALT-2024-007")
        result = agent.investigate(alert_07)

        assert result.verdict == Verdict.SUSPICIOUS
        assert result.recommended_action == RecommendedAction.ESCALATE

    def test_agent_all_8_scenarios_match_ground_truth(
        self,
        agent: SentinelInvestigationAgent,
        sample_alerts: list[Alert],
        ground_truth: dict,
    ) -> None:
        """Verify that agent's verdicts and actions match ground truth across all 8 scenarios."""
        for alert in sample_alerts:
            scenario_key = alert.scenario_id
            gt = ground_truth[scenario_key]

            result = agent.investigate(alert)

            assert result.verdict is not None
            assert result.recommended_action is not None
            assert result.verdict.value == gt["expected_verdict"], (
                f"Mismatch for {alert.id} ({scenario_key}): got {result.verdict.value}, expected {gt['expected_verdict']}"
            )
            assert result.recommended_action.value == gt["recommended_action"], (
                f"Action mismatch for {alert.id} ({scenario_key}): got {result.recommended_action.value}, expected {gt['recommended_action']}"
            )
            assert len(result.steps) == 6
            assert result.completed_at is not None
