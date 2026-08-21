"""ML-based severity scorer using RandomForest on investigation features.

This module handles:
1. Training a binary classifier (malicious vs benign) on synthetic data
   derived from the 8 investigation scenarios.
2. Inference: given features extracted from a new investigation, predict
   malicious probability (confidence score [0, 1]).

The model is serialized with joblib for fast reload. SHAP explainability
is available as an optional import.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)

from src.scoring.features import FEATURE_NAMES, extract_features
from src.models.alert import ThreatIntelResult


# Default model path
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "severity_model.joblib"


class MLScorer:
    """Binary malicious/benign classifier with confidence output.

    Wraps a RandomForestClassifier trained on investigation-level features.
    """

    def __init__(self, model_path: Path | str | None = None) -> None:
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self._model: RandomForestClassifier | None = None

        if self.model_path.is_file():
            self._model = joblib.load(self.model_path)

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def predict(
        self,
        threat_intel: list[ThreatIntelResult],
        patterns: list[dict[str, Any]],
        log_events: list[dict[str, Any]] | None = None,
    ) -> tuple[float, dict[str, float]]:
        """Predict malicious probability and feature importances.

        Returns (malicious_confidence [0,1], feature_importance_dict).
        """
        features = extract_features(threat_intel, patterns, log_events)

        if not self.is_trained:
            # Fallback: heuristic confidence based on feature values
            return self._heuristic_confidence(features), {}

        probas = self._model.predict_proba(features.reshape(1, -1))[0]
        # Class index 1 = malicious
        malicious_idx = list(self._model.classes_).index(1) if 1 in self._model.classes_ else 1
        malicious_confidence = float(probas[malicious_idx])

        importances = dict(zip(FEATURE_NAMES, self._model.feature_importances_))

        return malicious_confidence, importances

    def train(self, x_train: np.ndarray, y_train: np.ndarray) -> dict[str, float]:
        """Train the RandomForest classifier.

        Args:
            x_train: Feature matrix (n_samples, n_features).
            y_train: Labels (0=benign, 1=malicious).

        Returns metrics dict.
        """
        self._model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=3,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(x_train, y_train)

        y_pred = self._model.predict(x_train)
        metrics = {
            "accuracy": accuracy_score(y_train, y_pred),
            "precision": precision_score(y_train, y_pred, zero_division=0.0),
            "recall": recall_score(y_train, y_pred, zero_division=0.0),
            "f1": f1_score(y_train, y_pred, zero_division=0.0),
        }
        return metrics

    def save(self, path: Path | str | None = None) -> Path:
        """Serialize the trained model to disk."""
        save_path = Path(path) if path else self.model_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, save_path)
        return save_path

    @staticmethod
    def _heuristic_confidence(features: np.ndarray) -> float:
        """Fallback when no trained model is available.

        Uses simple weighted sum of key features normalized to [0, 1].
        """
        # Features: [ti_malicious_count, ti_max_confidence, ..., has_c2_exfil, ...]
        weights = np.zeros(len(FEATURE_NAMES))
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        weights[idx["ti_malicious_count"]] = 0.15
        weights[idx["ti_max_confidence"]] = 0.20
        weights[idx["has_brute_force"]] = 0.12
        weights[idx["has_c2_exfil"]] = 0.15
        weights[idx["has_recon_exec"]] = 0.12
        weights[idx["has_lateral_movement"]] = 0.08
        weights[idx["has_recon_only"]] = 0.04
        weights[idx["has_scheduled_task"]] = -0.10
        weights[idx["external_dest_count"]] = 0.03
        weights[idx["failed_auth_count"]] = 0.01

        raw = float(np.dot(weights, features))
        return max(0.0, min(1.0, raw))
