"""Combined severity scorer: rules + ML → final calibrated score.

Orchestrates:
1. Rule engine → explicit score [0, 100] + triggered rules
2. ML scorer → malicious probability [0, 1]
3. Weighted combination → final score [0, 100]
4. Severity classification → Low / Medium / Critical

Weights: rule_score * 0.4 + ml_confidence * 60 (scaled to [0,100])
Thresholds: < 30 = Low, 30-60 = Medium, > 60 = Critical
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.models.alert import (
    Severity,
    SeverityScore,
    ThreatIntelResult,
)
from src.scoring.features import FEATURE_NAMES
from src.scoring.ml_scorer import MLScorer
from src.scoring.rule_engine import RuleEngine


# Combination weights
RULE_WEIGHT = 0.4
ML_WEIGHT = 0.6

# Severity thresholds on the final [0, 100] scale
THRESHOLD_LOW_MEDIUM = 30.0
THRESHOLD_MEDIUM_CRITICAL = 60.0


class SeverityScorer:
    """Unified severity scoring combining explicit rules and ML confidence."""

    def __init__(self, model_path: Path | str | None = None) -> None:
        self.rule_engine = RuleEngine()
        self.ml_scorer = MLScorer(model_path=model_path)

    def score(
        self,
        threat_intel: list[ThreatIntelResult],
        patterns: list[dict[str, Any]],
        log_events: list[dict[str, Any]] | None = None,
    ) -> SeverityScore:
        """Compute combined severity score.

        Returns a fully populated SeverityScore with:
        - rule_score: explicit rules component [0, 100]
        - ml_confidence: ML malicious probability [0, 1]
        - final_score: weighted combination [0, 100]
        - severity: Low / Medium / Critical
        - rules_triggered: list of rule names that matched
        - ml_features_importance: top contributing ML features
        - explanation: human-readable breakdown
        """
        # 1. Rule engine evaluation
        rule_score, rule_matches = self.rule_engine.evaluate(
            threat_intel=threat_intel,
            patterns=patterns,
            log_events=log_events,
        )

        # 2. ML scorer prediction
        ml_confidence, ml_importances = self.ml_scorer.predict(
            threat_intel=threat_intel,
            patterns=patterns,
            log_events=log_events,
        )

        # 3. Weighted combination
        ml_scaled = ml_confidence * 100.0
        final_score = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_scaled)
        final_score = max(0.0, min(100.0, final_score))

        # 4. Severity classification
        severity = _classify_severity(final_score)

        # 5. Build explanation
        rules_triggered = [m.rule.name for m in rule_matches]
        explanation_parts = [
            f"Rule score: {rule_score:.1f}/100 ({len(rule_matches)} rules triggered)",
            f"ML confidence: {ml_confidence:.2f} ({_ml_model_status(self.ml_scorer)})",
            f"Combined: {RULE_WEIGHT:.0%} × {rule_score:.1f} + {ML_WEIGHT:.0%} × {ml_scaled:.1f} = {final_score:.1f}",
            f"Severity: {severity.value.upper()}",
        ]
        for m in rule_matches:
            sign = "+" if m.rule.weight >= 0 else ""
            explanation_parts.append(
                f"  [{m.rule.category}] {m.rule.name}: {sign}{m.rule.weight:.0f} pts — {m.evidence}"
            )

        # Top 5 ML feature importances
        top_features = dict(
            sorted(ml_importances.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        ) if ml_importances else {}

        return SeverityScore(
            rule_score=rule_score,
            ml_confidence=ml_confidence,
            final_score=final_score,
            severity=severity,
            rules_triggered=rules_triggered,
            ml_features_importance=top_features,
            explanation="\n".join(explanation_parts),
        )


def _classify_severity(score: float) -> Severity:
    if score > THRESHOLD_MEDIUM_CRITICAL:
        return Severity.CRITICAL
    if score >= THRESHOLD_LOW_MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW


def _ml_model_status(scorer: MLScorer) -> str:
    return "trained model" if scorer.is_trained else "heuristic fallback"
