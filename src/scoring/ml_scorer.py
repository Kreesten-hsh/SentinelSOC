"""ML-based severity scorer using RandomForest on investigation features.

This module handles:
1. Training a binary classifier (malicious vs benign) on features derived
   from SOC investigation archetypes.
2. Inference: given features extracted from a new investigation, predict
   malicious probability (confidence score [0, 1]).
3. Automatic bootstrap: ensures the model file exists or generates it on first load.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)

from src.models.alert import ThreatIntelResult
from src.scoring.features import FEATURE_NAMES, extract_features
from src.scoring.training_data import generate_training_data

logger = logging.getLogger("sentinelsoc.ml_scorer")

# Default model path
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "severity_model.joblib"


class MLScorer:
    """Binary malicious/benign classifier with confidence output.

    Wraps a RandomForestClassifier trained on investigation-level features.
    """

    def __init__(self, model_path: Path | str | None = None, auto_bootstrap: bool = True) -> None:
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self._model: RandomForestClassifier | None = None

        if self.model_path.is_file():
            try:
                self._model = joblib.load(self.model_path)
            except Exception as e:
                logger.error("Failed to load ML model from %s: %s", self.model_path, e)
                self._model = None

        if self._model is None:
            if auto_bootstrap:
                try:
                    logger.info("ML model absent at '%s'. Auto-training RandomForest model...", self.model_path)
                    self.auto_train_and_save()
                except Exception as err:
                    logger.warning(
                        "CRITICAL WARNING: Auto-training failed (%s). Falling back to uncalibrated heuristic scoring. "
                        "Run 'python3 scripts/train_severity_model.py' to restore ML precision.",
                        err,
                    )
            else:
                logger.warning(
                    "CRITICAL WARNING: ML model '%s' not found! Falling back to uncalibrated heuristic scoring. "
                    "Run 'python3 scripts/train_severity_model.py' to restore ML precision.",
                    self.model_path,
                )

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def auto_train_and_save(self) -> dict[str, float]:
        """Automatically generate dataset, train classifier, and save to model_path."""
        x_train, y_train = generate_training_data()
        metrics = self.train(x_train, y_train)
        self.save(self.model_path)
        logger.info("RandomForest model trained and saved to %s (Accuracy: %.4f, F1: %.4f)", self.model_path, metrics["accuracy"], metrics["f1"])
        return metrics

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
            logger.warning("Predict called without trained model. Using heuristic fallback.")
            return self._heuristic_confidence(features), {}

        assert self._model is not None
        probas = self._model.predict_proba(features.reshape(1, -1))[0]
        # Class index 1 = malicious
        classes_list = list(self._model.classes_)
        malicious_idx = classes_list.index(1) if 1 in classes_list else 1
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
            "accuracy": float(accuracy_score(y_train, y_pred)),
            "precision": float(precision_score(y_train, y_pred, zero_division=0.0)),
            "recall": float(recall_score(y_train, y_pred, zero_division=0.0)),
            "f1": float(f1_score(y_train, y_pred, zero_division=0.0)),
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
