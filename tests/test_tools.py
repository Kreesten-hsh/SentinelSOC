"""Unit tests for the 4 smolagents investigation tools."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.data.log_store import LogStore
from src.tools.correlator import EventCorrelatorTool, is_external_ip
from src.tools.ioc_extractor import IOCExtractorTool, extract_iocs_from_text
from src.tools.log_query import LogQueryTool
from src.tools.threat_intel import ThreatIntelTool


@pytest.fixture
def scenarios_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "scenarios"


@pytest.fixture
def log_store(scenarios_path: Path) -> LogStore:
    return LogStore(scenarios_path)


# ──────────────── External IP Helper Tests ────────────────


class TestIPClassification:
    def test_is_external_ip_public_addresses(self) -> None:
        assert is_external_ip("23.22.63.114") is True
        assert is_external_ip("40.80.148.42") is True
        assert is_external_ip("185.141.27.88") is True
        assert is_external_ip("91.234.99.42") is True
        assert is_external_ip("198.71.247.91") is True
        assert is_external_ip("8.8.8.8") is True

    def test_is_external_ip_private_rfc1918(self) -> None:
        assert is_external_ip("192.168.250.70") is False
        assert is_external_ip("192.168.1.1") is False
        assert is_external_ip("10.0.0.88") is False
        assert is_external_ip("172.16.0.5") is False

    def test_is_external_ip_broadcast_loopback_invalid(self) -> None:
        assert is_external_ip("192.168.250.255") is False
        assert is_external_ip("127.0.0.1") is False
        assert is_external_ip("255.255.255.255") is False
        assert is_external_ip("invalid_ip") is False
        assert is_external_ip("") is False


# ──────────────── IOC Extractor Tool Tests ────────────────


class TestIOCExtractorTool:
    def test_extract_ips_and_hashes(self) -> None:
        tool = IOCExtractorTool()
        text = "Observed outbound connection to 23.22.63.114 with hash d41d8cd98f00b204e9800998ecf8427e2b3f68c1a8e5d7c933b9f4e2460b13d6 from host ws-bobsmith"
        res_raw = tool.forward(content=text, alert_id="ALT-TEST")
        res = json.loads(res_raw)

        assert res["alert_id"] == "ALT-TEST"
        assert "23.22.63.114" in res["ips"]
        assert "d41d8cd98f00b204e9800998ecf8427e2b3f68c1a8e5d7c933b9f4e2460b13d6" in res["hashes"]
        assert any(i["type"] == "hostname" and i["value"] == "ws-bobsmith" for i in res["all_iocs"])

    def test_extract_from_json_payload(self) -> None:
        tool = IOCExtractorTool()
        payload = json.dumps({
            "src_ip": "40.80.148.42",
            "dest_ip": "192.168.250.50",
            "user": "WAYNE\\bob.smith",
            "host": "srv-dc01",
            "domain": "dropzone-files.xyz",
        })
        res = json.loads(tool.forward(content=payload))
        assert "40.80.148.42" in res["ips"]
        assert "192.168.250.50" in res["ips"]
        assert "WAYNE\\bob.smith" in res["users"]
        assert "dropzone-files.xyz" in res["domains"]

    def test_extract_iocs_from_text_helper(self) -> None:
        iocs = extract_iocs_from_text("Connection from 10.0.0.88 to evil.com")
        values = {i.value for i in iocs}
        assert "10.0.0.88" in values
        assert "evil.com" in values


# ──────────────── Log Query Tool Tests ────────────────


class TestLogQueryTool:
    def test_query_by_scenario_id(self, log_store: LogStore) -> None:
        tool = LogQueryTool(log_store=log_store)
        res_raw = tool.forward(scenario_id="scenario_01_web_defacement")
        res = json.loads(res_raw)

        assert res["total_matches"] == 14
        assert res["returned_count"] == 14
        assert any(e["src_ip"] == "23.22.63.114" for e in res["events"])

    def test_query_by_ip_and_source_type(self, log_store: LogStore) -> None:
        tool = LogQueryTool(log_store=log_store)
        res = json.loads(tool.forward(src_ip="23.22.63.114", source_type="ids"))
        assert res["returned_count"] >= 1
        assert all(e["source_type"] == "ids" for e in res["events"])

    def test_query_by_user(self, log_store: LogStore) -> None:
        tool = LogQueryTool(log_store=log_store)
        res = json.loads(tool.forward(user="WAYNE\\bob.smith"))
        assert res["total_matches"] > 0
        assert any(e["user"] == "WAYNE\\bob.smith" for e in res["events"])


# ──────────────── Event Correlator Tool Tests ────────────────


class TestEventCorrelatorTool:
    def test_correlate_scenario_01_web_defacement(self, log_store: LogStore) -> None:
        tool = EventCorrelatorTool(log_store=log_store)
        res_raw = tool.forward(scenario_id="scenario_01_web_defacement")
        res = json.loads(res_raw)

        assert res["correlation_summary"]["total_events_correlated"] == 14
        assert "23.22.63.114" in res["correlation_summary"]["unique_ips"]
        patterns = [p["pattern"] for p in res["detected_attack_patterns"]]
        assert "reconnaissance_followed_by_execution" in patterns

    def test_correlate_scenario_02_brute_force(self, log_store: LogStore) -> None:
        tool = EventCorrelatorTool(log_store=log_store)
        res = json.loads(tool.forward(scenario_id="scenario_02_brute_force"))

        assert res["correlation_summary"]["total_events_correlated"] == 33
        patterns = [p["pattern"] for p in res["detected_attack_patterns"]]
        assert "brute_force_followed_by_success" in patterns

    def test_correlate_scenario_05_reconnaissance_only(self, log_store: LogStore) -> None:
        tool = EventCorrelatorTool(log_store=log_store)
        res = json.loads(tool.forward(scenario_id="scenario_05_reconnaissance"))

        patterns = [p["pattern"] for p in res["detected_attack_patterns"]]
        assert "reconnaissance_only" in patterns
        assert "reconnaissance_followed_by_execution" not in patterns

    def test_correlate_scenario_06_scheduled_task_only(self, log_store: LogStore) -> None:
        tool = EventCorrelatorTool(log_store=log_store)
        res = json.loads(tool.forward(scenario_id="scenario_06_false_positive"))

        patterns = [p["pattern"] for p in res["detected_attack_patterns"]]
        assert "scheduled_task_triggered_execution" in patterns
        assert "command_and_control_or_exfiltration" not in patterns  # Confirms external IP fix!

    def test_correlate_scenario_07_lateral_movement_dual_use(self, log_store: LogStore) -> None:
        tool = EventCorrelatorTool(log_store=log_store)
        res = json.loads(tool.forward(scenario_id="scenario_07_ambiguous_lateral"))

        patterns = [p["pattern"] for p in res["detected_attack_patterns"]]
        assert "lateral_movement_dual_use_tool" in patterns

    def test_correlate_no_events_returns_empty_structure(self, log_store: LogStore) -> None:
        tool = EventCorrelatorTool(log_store=log_store)
        res = json.loads(tool.forward(target_ip="199.199.199.199"))
        assert res["status"] == "no_events_found"


# ──────────────── Threat Intel Tool Tests ────────────────


class TestThreatIntelTool:
    def test_lookup_known_malicious_ip(self) -> None:
        tool = ThreatIntelTool()
        res = json.loads(tool.forward(ioc_value="23.22.63.114"))
        assert res["reputation"] == "malicious"
        assert res["confidence"] >= 0.9
        assert "acunetix" in res["tags"]

    def test_lookup_known_c2_ip(self) -> None:
        tool = ThreatIntelTool()
        res = json.loads(tool.forward(ioc_value="185.141.27.88"))
        assert res["reputation"] == "malicious"
        assert "cerber" in res["tags"]

    def test_lookup_clean_internal_ip(self) -> None:
        tool = ThreatIntelTool()
        res = json.loads(tool.forward(ioc_value="192.168.250.50"))
        assert res["reputation"] == "clean"
        assert res["confidence"] > 0.9

    def test_lookup_unknown_ip(self) -> None:
        tool = ThreatIntelTool()
        res = json.loads(tool.forward(ioc_value="8.8.8.8"))
        assert res["reputation"] == "unknown"
        assert res["confidence"] == 0.0

    def test_lookup_abuseipdb_api_fallback(self) -> None:
        from unittest.mock import MagicMock, patch

        tool = ThreatIntelTool()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "198.51.100.23",
                "abuseConfidenceScore": 85,
                "countryCode": "US",
            }
        }

        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "fake_test_key"}):
            with patch("httpx.get", return_value=mock_resp) as mock_get:
                res = json.loads(tool.forward(ioc_value="198.51.100.23"))
                assert res["reputation"] == "malicious"
                assert res["confidence"] == 0.85
                assert res["source"] == "abuseipdb_api"
                mock_get.assert_called_once()
