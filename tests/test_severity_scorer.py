"""Unit tests for the severity scoring engine (rules, ML, combined)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.models.alert import IOCType, Severity, ThreatIntelResult
from src.scoring.features import FEATURE_NAMES, extract_features
from src.scoring.ml_scorer import MLScorer
from src.scoring.rule_engine import RuleEngine
from src.scoring.severity_scorer import SeverityScorer


@pytest.fixture
def model_path() -> Path:
    return Path(__file__).resolve().parent.parent / "models" / "severity_model.joblib"


# ──────────────── Rule Engine Tests ────────────────


class TestRuleEngine:
    def test_malicious_ti_triggers_high_weight(self) -> None:
        engine = RuleEngine()
        ti = [ThreatIntelResult(ioc_value="1.2.3.4", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.95)]
        score, matches = engine.evaluate(threat_intel=ti, patterns=[])
        rule_names = [m.rule.name for m in matches]
        assert "ti_malicious_high_confidence" in rule_names
        assert score >= 30.0

    def test_critical_pattern_adds_high_weight(self) -> None:
        engine = RuleEngine()
        patterns = [{"pattern": "brute_force_followed_by_success", "severity": "critical", "description": "test"}]
        score, matches = engine.evaluate(threat_intel=[], patterns=patterns)
        rule_names = [m.rule.name for m in matches]
        assert "pattern_brute_force_success" in rule_names
        assert score >= 30.0

    def test_scheduled_task_reduces_score(self) -> None:
        engine = RuleEngine()
        patterns = [{"pattern": "scheduled_task_triggered_execution", "severity": "low", "description": "test"}]
        score, matches = engine.evaluate(threat_intel=[], patterns=patterns)
        rule_names = [m.rule.name for m in matches]
        assert "pattern_scheduled_task" in rule_names
        # Negative weight should yield low score
        assert score < 10.0

    def test_clean_ti_subtracts_score(self) -> None:
        engine = RuleEngine()
        ti = [ThreatIntelResult(ioc_value="192.168.1.1", ioc_type=IOCType.IPV4, reputation="clean", confidence=0.99)]
        score, matches = engine.evaluate(threat_intel=ti, patterns=[])
        rule_names = [m.rule.name for m in matches]
        assert "clean_threat_intel" in rule_names

    def test_multiple_rules_accumulate(self) -> None:
        engine = RuleEngine()
        ti = [ThreatIntelResult(ioc_value="1.2.3.4", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.95)]
        patterns = [{"pattern": "command_and_control_or_exfiltration", "severity": "critical", "description": "c2"}]
        score, matches = engine.evaluate(threat_intel=ti, patterns=patterns)
        # Should accumulate ti_malicious_high (40) + pattern_c2_exfil (40) = 80
        assert score >= 70.0
        assert len(matches) >= 2


# ──────────────── Feature Extraction Tests ────────────────


class TestFeatureExtraction:
    def test_feature_vector_length(self) -> None:
        features = extract_features(threat_intel=[], patterns=[])
        assert len(features) == len(FEATURE_NAMES)

    def test_malicious_ti_features(self) -> None:
        ti = [ThreatIntelResult(ioc_value="1.2.3.4", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.9)]
        features = extract_features(threat_intel=ti, patterns=[])
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert features[idx["ti_malicious_count"]] == 1.0
        assert features[idx["ti_max_confidence"]] == 0.9

    def test_pattern_features(self) -> None:
        patterns = [
            {"pattern": "brute_force_followed_by_success", "severity": "critical"},
            {"pattern": "reconnaissance_only", "severity": "medium"},
        ]
        features = extract_features(threat_intel=[], patterns=patterns)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert features[idx["has_brute_force"]] == 1.0
        assert features[idx["has_recon_only"]] == 1.0
        assert features[idx["pattern_count_critical"]] == 1.0
        assert features[idx["pattern_count_medium"]] == 1.0


# ──────────────── ML Scorer Tests ────────────────


class TestMLScorer:
    def test_heuristic_fallback_when_no_model(self) -> None:
        scorer = MLScorer(model_path=Path("/nonexistent/model.joblib"))
        ti = [ThreatIntelResult(ioc_value="1.2.3.4", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.9)]
        confidence, importances = scorer.predict(threat_intel=ti, patterns=[])
        assert 0.0 <= confidence <= 1.0
        assert importances == {}  # No importances in heuristic mode

    def test_trained_model_predictions(self, model_path: Path) -> None:
        if not model_path.is_file():
            pytest.skip("Trained model not available")
        scorer = MLScorer(model_path=model_path)

        # Malicious scenario
        ti_mal = [ThreatIntelResult(ioc_value="1.2.3.4", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.95)]
        p_crit = [{"pattern": "brute_force_followed_by_success", "severity": "critical"}]
        conf, imp = scorer.predict(threat_intel=ti_mal, patterns=p_crit)
        assert conf > 0.5  # Should predict malicious

        # Benign scenario
        conf_b, _ = scorer.predict(threat_intel=[], patterns=[])
        assert conf_b < 0.5  # Should predict benign


# ──────────────── Combined Severity Scorer Tests ────────────────


class TestSeverityScorer:
    def test_critical_scenario(self, model_path: Path) -> None:
        scorer = SeverityScorer(model_path=model_path)
        ti = [ThreatIntelResult(ioc_value="1.2.3.4", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.95)]
        patterns = [{"pattern": "command_and_control_or_exfiltration", "severity": "critical"}]
        result = scorer.score(threat_intel=ti, patterns=patterns)
        assert result.severity == Severity.CRITICAL
        assert result.final_score > 60.0
        assert len(result.rules_triggered) >= 2
        assert result.explanation

    def test_benign_scenario(self, model_path: Path) -> None:
        scorer = SeverityScorer(model_path=model_path)
        patterns = [{"pattern": "scheduled_task_triggered_execution", "severity": "low"}]
        result = scorer.score(threat_intel=[], patterns=patterns)
        assert result.severity == Severity.LOW
        assert result.final_score < 30.0

    def test_medium_scenario(self, model_path: Path) -> None:
        scorer = SeverityScorer(model_path=model_path)
        patterns = [{"pattern": "lateral_movement_dual_use_tool", "severity": "medium"}]
        result = scorer.score(threat_intel=[], patterns=patterns)
        assert result.severity == Severity.MEDIUM
        assert 30.0 <= result.final_score <= 60.0

    def test_all_8_scenarios_match_expected_severity(self, model_path: Path) -> None:
        """Verify severity alignment with ground truth across all 8 scenarios."""
        import json
        gt_path = Path(__file__).resolve().parent.parent / "data" / "scenarios" / "ground_truth.json"
        with gt_path.open("r") as fh:
            gt = json.load(fh)["scenarios"]

        scorer = SeverityScorer(model_path=model_path)

        scenario_evidence = {
            "scenario_01_web_defacement": (
                [ThreatIntelResult(ioc_value="23.22.63.114", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.95)],
                [{"pattern": "reconnaissance_followed_by_execution", "severity": "critical"}],
            ),
            "scenario_02_brute_force": (
                [ThreatIntelResult(ioc_value="40.80.148.42", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.92)],
                [{"pattern": "brute_force_followed_by_success", "severity": "critical"}],
            ),
            "scenario_03_ransomware": (
                [ThreatIntelResult(ioc_value="185.141.27.88", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.99)],
                [{"pattern": "command_and_control_or_exfiltration", "severity": "critical"}],
            ),
            "scenario_04_data_exfiltration": (
                [ThreatIntelResult(ioc_value="91.234.99.42", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.88)],
                [{"pattern": "command_and_control_or_exfiltration", "severity": "critical"}],
            ),
            "scenario_05_reconnaissance": (
                [],
                [{"pattern": "reconnaissance_only", "severity": "medium"}],
            ),
            "scenario_06_false_positive": (
                [],
                [{"pattern": "scheduled_task_triggered_execution", "severity": "low"}],
            ),
            "scenario_07_ambiguous_lateral": (
                [],
                [{"pattern": "lateral_movement_dual_use_tool", "severity": "medium"}],
            ),
            "scenario_08_credential_stuffing": (
                [ThreatIntelResult(ioc_value="198.71.247.91", ioc_type=IOCType.IPV4, reputation="malicious", confidence=0.90)],
                [{"pattern": "brute_force_followed_by_success", "severity": "critical"}],
            ),
        }

        for scenario_id, (ti, patterns) in scenario_evidence.items():
            expected_sev = gt[scenario_id]["expected_severity"]
            result = scorer.score(threat_intel=ti, patterns=patterns)
            assert result.severity.value == expected_sev, (
                f"{scenario_id}: got {result.severity.value}, expected {expected_sev} (score={result.final_score:.1f})"
            )
