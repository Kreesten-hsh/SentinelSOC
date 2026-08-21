"""Tests for SentinelInvestigationAgent LLM mode (smolagents integration)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.data.log_store import LogStore
from src.models.alert import Alert, AlertStatus, Severity


@pytest.fixture
def sample_alert() -> Alert:
    return Alert(
        id="ALT-TEST-001",
        timestamp=datetime.now(timezone.utc),
        source="fortinet_firewall",
        title="Suspicious Outbound Connection",
        description="Outbound connection to 23.22.63.114 on port 80",
        raw_data={"src_ip": "10.0.0.50", "dest_ip": "23.22.63.114", "dest_port": 80},
        status=AlertStatus.PENDING,
        severity=Severity.CRITICAL,
        scenario_id="scenario_01_web_defacement",
    )


def test_llm_agent_initialization(sample_alert: Alert) -> None:
    """Verify that use_llm=True initializes tools and CodeAgent plumbing properly."""
    agent = SentinelInvestigationAgent(use_llm=False)
    assert len(agent.tools) == 4
    assert agent.ioc_tool.name == "extract_iocs"
    assert agent.log_tool.name == "query_logs"
    assert agent.corr_tool.name == "correlate_events"
    assert agent.ti_tool.name == "lookup_threat_intel"


def test_investigate_llm_execution_with_mock_model(sample_alert: Alert) -> None:
    """Verify that investigate_llm orchestrates smolagents CodeAgent and returns synthesis."""
    agent = SentinelInvestigationAgent(use_llm=False)

    # Mock the internal CodeAgent run method
    mock_code_agent = MagicMock()
    mock_code_agent.run.return_value = (
        "Investigation complete.\n"
        "Verdict: TRUE_POSITIVE\n"
        "Action: CONTAIN\n"
        "Reason: Malicious IP 23.22.63.114 detected in threat intel feed."
    )
    agent._llm_agent = mock_code_agent

    result_text = agent.investigate_llm(sample_alert)
    assert "TRUE_POSITIVE" in result_text
    assert "CONTAIN" in result_text
    mock_code_agent.run.assert_called_once()
