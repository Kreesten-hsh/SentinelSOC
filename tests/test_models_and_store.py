"""Tests pour les modèles de données et le log store."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.models.alert import (
    Alert,
    AlertStatus,
    CorrelationFinding,
    IOC,
    IOCCollection,
    IOCType,
    InvestigationResult,
    InvestigationStep,
    LogEvent,
    LogSourceType,
    Severity,
    SeverityScore,
    ThreatIntelResult,
    Verdict,
)
from src.data.log_store import LogStore


# ──────────────── IOC Model Tests ────────────────


class TestIOC:
    def test_create_ipv4_ioc(self) -> None:
        ioc = IOC(ioc_type=IOCType.IPV4, value="23.22.63.114", context="Source IP from alert")
        assert ioc.ioc_type == IOCType.IPV4
        assert ioc.value == "23.22.63.114"
        assert ioc.context == "Source IP from alert"

    def test_create_hash_ioc(self) -> None:
        ioc = IOC(ioc_type=IOCType.SHA256, value="d41d8cd98f00b204e9800998ecf8427e")
        assert ioc.ioc_type == IOCType.SHA256

    def test_ioc_collection_properties(self) -> None:
        collection = IOCCollection(
            alert_id="ALT-001",
            iocs=[
                IOC(ioc_type=IOCType.IPV4, value="1.2.3.4"),
                IOC(ioc_type=IOCType.IPV4, value="5.6.7.8"),
                IOC(ioc_type=IOCType.DOMAIN, value="evil.com"),
                IOC(ioc_type=IOCType.SHA256, value="abcdef1234567890"),
                IOC(ioc_type=IOCType.USER, value="admin"),
            ],
        )
        assert len(collection.ips) == 2
        assert len(collection.domains) == 1
        assert len(collection.hashes) == 1
        assert len(collection.users) == 1


# ──────────────── Alert Model Tests ────────────────


class TestAlert:
    def test_create_alert(self) -> None:
        alert = Alert(
            id="ALT-2024-001",
            timestamp=datetime(2024, 8, 10, 14, 20),
            source="Suricata IDS",
            title="Web Scanner Detected",
            description="Acunetix scan from 23.22.63.114",
            raw_data={"src_ip": "23.22.63.114"},
        )
        assert alert.status == AlertStatus.PENDING
        assert alert.severity is None
        assert alert.raw_data["src_ip"] == "23.22.63.114"

    def test_alert_serialization_roundtrip(self) -> None:
        alert = Alert(
            id="ALT-TEST",
            timestamp=datetime(2024, 1, 1),
            source="test",
            title="Test Alert",
            description="Test",
        )
        json_str = alert.model_dump_json()
        restored = Alert.model_validate_json(json_str)
        assert restored.id == alert.id
        assert restored.timestamp == alert.timestamp


# ──────────────── LogEvent Model Tests ────────────────


class TestLogEvent:
    def test_create_firewall_event(self) -> None:
        event = LogEvent(
            timestamp=datetime(2024, 8, 10, 14, 20),
            source_type=LogSourceType.FIREWALL,
            src_ip="23.22.63.114",
            dest_ip="192.168.250.70",
            src_port=49152,
            dest_port=80,
            action="allow",
            host="fw-01",
        )
        assert event.source_type == LogSourceType.FIREWALL
        assert event.dest_port == 80

    def test_create_auth_event(self) -> None:
        event = LogEvent(
            timestamp=datetime(2024, 8, 11, 3, 15),
            source_type=LogSourceType.AUTH,
            src_ip="40.80.148.42",
            user="admin",
            host="srv-dc01",
            action="login_failed",
            metadata={"event_id": 4625, "failure_reason": "bad_password"},
        )
        assert event.source_type == LogSourceType.AUTH
        assert event.metadata["event_id"] == 4625


# ──────────────── Investigation Model Tests ────────────────


class TestInvestigationModels:
    def test_investigation_step(self) -> None:
        step = InvestigationStep(
            step_number=1,
            action="Query firewall logs for IP 23.22.63.114",
            reasoning="The alert references this IP as the source — checking network activity first",
            tool_used="log_query",
            events_found=5,
        )
        assert step.step_number == 1
        assert step.events_found == 5

    def test_severity_score_validation(self) -> None:
        score = SeverityScore(
            rule_score=70.0,
            ml_confidence=0.89,
            final_score=81.0,
            severity=Severity.CRITICAL,
            rules_triggered=["IP in threat intel", "Web scanner detected"],
        )
        assert score.severity == Severity.CRITICAL
        assert len(score.rules_triggered) == 2

    def test_severity_score_bounds(self) -> None:
        with pytest.raises(Exception):
            SeverityScore(
                rule_score=150.0,  # > 100 → validation error
                ml_confidence=0.5,
                final_score=50.0,
                severity=Severity.LOW,
            )

    def test_threat_intel_result(self) -> None:
        result = ThreatIntelResult(
            ioc_value="23.22.63.114",
            ioc_type=IOCType.IPV4,
            reputation="malicious",
            confidence=0.95,
            tags=["scanner", "acunetix"],
            source="local",
        )
        assert result.reputation == "malicious"
        assert result.confidence == 0.95

    def test_full_investigation_result(self) -> None:
        result = InvestigationResult(
            alert_id="ALT-001",
            iocs=IOCCollection(alert_id="ALT-001"),
            verdict=Verdict.TRUE_POSITIVE,
        )
        assert result.verdict == Verdict.TRUE_POSITIVE
        assert result.completed_at is None


# ──────────────── LogStore Tests ────────────────


class TestLogStore:
    @pytest.fixture
    def sample_events(self) -> list[LogEvent]:
        base = datetime(2024, 8, 10, 14, 20)
        return [
            LogEvent(
                timestamp=base,
                source_type=LogSourceType.FIREWALL,
                src_ip="23.22.63.114",
                dest_ip="192.168.250.70",
                dest_port=80,
                action="allow",
                host="fw-01",
                scenario_id="test_scenario",
            ),
            LogEvent(
                timestamp=base + timedelta(minutes=1),
                source_type=LogSourceType.IDS,
                src_ip="23.22.63.114",
                dest_ip="192.168.250.70",
                action="alert",
                host="ids-01",
                metadata={"signature": "ET SCAN Acunetix"},
                scenario_id="test_scenario",
            ),
            LogEvent(
                timestamp=base + timedelta(minutes=2),
                source_type=LogSourceType.AUTH,
                src_ip="192.168.250.10",
                user="admin",
                host="srv-dc01",
                action="login_success",
                scenario_id="test_scenario",
            ),
            LogEvent(
                timestamp=base + timedelta(hours=2),
                source_type=LogSourceType.FIREWALL,
                src_ip="10.0.0.88",
                dest_ip="192.168.250.50",
                dest_port=445,
                action="allow",
                host="fw-01",
                scenario_id="other_scenario",
            ),
        ]

    @pytest.fixture
    def store_with_events(self, sample_events: list[LogEvent]) -> LogStore:
        store = LogStore()
        for event in sample_events:
            store.add_event(event)
        return store

    def test_event_count(self, store_with_events: LogStore) -> None:
        assert store_with_events.event_count == 4

    def test_scenarios_loaded(self, store_with_events: LogStore) -> None:
        assert store_with_events.scenarios_loaded == {"test_scenario", "other_scenario"}

    def test_query_by_src_ip(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_src_ip("23.22.63.114")
        assert len(results) == 2

    def test_query_by_src_ip_with_source_type(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_src_ip("23.22.63.114", source_type=LogSourceType.IDS)
        assert len(results) == 1
        assert results[0].source_type == LogSourceType.IDS

    def test_query_by_dest_ip(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_dest_ip("192.168.250.70")
        assert len(results) == 2

    def test_query_by_user(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_user("admin")
        assert len(results) == 1
        assert results[0].action == "login_success"

    def test_query_by_user_case_insensitive(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_user("Admin")
        assert len(results) == 1

    def test_query_firewall_logs(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_firewall_logs(src_ip="23.22.63.114")
        assert len(results) == 1
        assert results[0].source_type == LogSourceType.FIREWALL

    def test_query_auth_logs(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_auth_logs(user="admin")
        assert len(results) == 1

    def test_query_with_time_window(self, store_with_events: LogStore) -> None:
        base = datetime(2024, 8, 10, 14, 20)
        results = store_with_events.query_around_timestamp(base, window_minutes=5)
        assert len(results) == 3  # Exclut l'événement 2h plus tard

    def test_query_by_scenario(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_scenario("test_scenario")
        assert len(results) == 3

    def test_results_sorted_by_timestamp(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_scenario("test_scenario")
        timestamps = [e.timestamp for e in results]
        assert timestamps == sorted(timestamps)

    def test_load_from_jsonl(self, sample_events: list[LogEvent]) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            jsonl_path = Path(tmpdir) / "test.jsonl"
            with jsonl_path.open("w") as fh:
                for event in sample_events:
                    fh.write(event.model_dump_json() + "\n")

            store = LogStore()
            store.load_scenario_file(jsonl_path)
            assert store.event_count == 4

    def test_empty_query_returns_empty(self, store_with_events: LogStore) -> None:
        results = store_with_events.query_by_src_ip("99.99.99.99")
        assert len(results) == 0
