"""Train the severity ML model on synthetic investigation-level features.

Generates training data from the 8 known scenarios + augmented variations,
trains a RandomForest binary classifier, evaluates on a held-out split,
and serializes the model.

Usage:
    python3 scripts/train_severity_model.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sklearn.model_selection import StratifiedKFold, cross_val_score

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.scoring.features import FEATURE_NAMES
from src.scoring.ml_scorer import MLScorer
from src.scoring.training_data import generate_training_data
from src.models.alert import IOCType, ThreatIntelResult


def main() -> None:
    print("=" * 70)
    print("SentinelSOC — ML Severity Model Training")
    print("=" * 70)

    # Generate training data
    x, y = generate_training_data()
    print(f"\nTraining data: {x.shape[0]} samples, {x.shape[1]} features")
    print(f"Class distribution: benign={int((y == 0).sum())}, malicious={int((y == 1).sum())}")

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scorer = MLScorer(auto_bootstrap=False)
    scorer._model = None  # Ensure fresh training

    # Train on full dataset for final model
    metrics = scorer.train(x, y)
    print(f"\nTraining metrics (on training set):")
    for k, v in metrics.items():
        print(f"  {k}: {v:.4f}")

    # Cross-validation for honest estimate
    from sklearn.ensemble import RandomForestClassifier
    cv_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=3,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    cv_scores = cross_val_score(cv_model, x, y, cv=cv, scoring="f1")
    print(f"\n5-Fold Cross-Validation F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"  Per-fold: {[f'{s:.4f}' for s in cv_scores]}")

    # Save model
    model_path = scorer.save()
    print(f"\nModel saved to: {model_path}")

    # Feature importances
    assert scorer._model is not None
    print("\nTop 10 Feature Importances:")
    importances = sorted(
        zip(FEATURE_NAMES, scorer._model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, imp in importances[:10]:
        bar = "█" * int(imp * 50)
        print(f"  {name:<30} {imp:.4f} {bar}")

    # Verify on the 8 original scenarios
    print("\n" + "=" * 70)
    print("Verification on 8 Original Scenarios")
    print("=" * 70)

    gt_path = PROJECT_ROOT / "data" / "scenarios" / "ground_truth.json"
    with gt_path.open("r") as fh:
        gt = json.load(fh)["scenarios"]

    scenario_features = {
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

    from src.scoring.severity_scorer import SeverityScorer
    combined_scorer = SeverityScorer(model_path=model_path)

    for scenario_id, (ti, patterns) in scenario_features.items():
        gt_sev = gt[scenario_id]["expected_severity"]
        result = combined_scorer.score(threat_intel=ti, patterns=patterns)
        match = "✓" if result.severity.value == gt_sev else "✗"
        print(f"  {match} {scenario_id}: score={result.final_score:.1f} severity={result.severity.value.upper()} (expected={gt_sev.upper()})")


if __name__ == "__main__":
    main()
