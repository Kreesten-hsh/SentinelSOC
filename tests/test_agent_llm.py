"""Real unit and integration tests for SentinelInvestigationAgent LLM mode (smolagents CodeAgent).

These tests verify:
1. Real instantiation of smolagents.CodeAgent via SentinelInvestigationAgent(use_llm=True).
2. Inspection of CodeAgent constructor parameters, tool bindings, and prompt instructions.
3. Real CodeAgent execution loop with mock LLM model outputs (verifying code parsing & final answer resolution).
4. Explicit error logging on initialization failure without silent exception swallowing.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from smolagents import CodeAgent
from smolagents.models import ChatMessage

from src.agent.prompts import INVESTIGATION_SYSTEM_PROMPT
from src.agent.sentinel_agent import SentinelInvestigationAgent
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


def test_real_llm_agent_initialization() -> None:
    """Verify that SentinelInvestigationAgent(use_llm=True) instantiates a real smolagents.CodeAgent."""
    agent = SentinelInvestigationAgent(use_llm=True, model_name="ollama/mistral")

    assert agent.use_llm is True
    assert agent._llm_agent is not None
    assert isinstance(agent._llm_agent, CodeAgent)

    # Verify our 4 custom tools are registered inside the real CodeAgent instance
    assert len(agent.tools) == 4
    custom_tool_names = {"extract_iocs", "query_logs", "correlate_events", "lookup_threat_intel"}
    assert custom_tool_names.issubset(set(agent._llm_agent.tools.keys()))

    # Verify that instructions are passed to CodeAgent
    assert agent._llm_agent.instructions == INVESTIGATION_SYSTEM_PROMPT


def test_llm_agent_initialization_failure_logs_explicit_error(caplog: pytest.LogCaptureFixture) -> None:
    """Verify that initialization failures are logged explicitly with exc_info instead of swallowed."""
    with patch("smolagents.CodeAgent", side_effect=TypeError("Unexpected mock param error")):
        with caplog.at_level(logging.ERROR):
            agent = SentinelInvestigationAgent(use_llm=True, model_name="ollama/mistral")
            assert agent._llm_agent is None
            assert "LLM CodeAgent initialization failed: Unexpected mock param error" in caplog.text


def test_investigate_llm_real_codeagent_execution_loop(sample_alert: Alert) -> None:
    """Verify that investigate_llm orchestrates a real CodeAgent run and parsing loop."""
    agent = SentinelInvestigationAgent(use_llm=True, model_name="ollama/mistral")
    assert agent._llm_agent is not None

    # Inject mock Model output into the real CodeAgent instance
    mock_model = MagicMock()
    mock_model.generate.return_value = ChatMessage(
        role="assistant",
        content='```python\nfinal_answer("Investigation complete. Verdict: TRUE_POSITIVE. Action: CONTAIN. Reason: Outbound C2 traffic confirmed.")\n```',
    )
    agent._llm_agent.model = mock_model

    result_text = agent.investigate_llm(sample_alert)

    assert "TRUE_POSITIVE" in result_text
    assert "CONTAIN" in result_text
    assert "Outbound C2 traffic confirmed" in result_text
    mock_model.generate.assert_called()


def test_investigate_llm_raises_clear_error_when_uninitialized(sample_alert: Alert) -> None:
    """Verify investigate_llm raises a clear RuntimeError if CodeAgent cannot be initialized."""
    agent = SentinelInvestigationAgent(use_llm=False)
    with patch.object(agent, "_init_llm_agent", return_value=None):
        agent._llm_agent = None
        with pytest.raises(RuntimeError, match="Failed to initialize LLM CodeAgent"):
            agent.investigate_llm(sample_alert)
