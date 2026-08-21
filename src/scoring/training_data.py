"""Training dataset generator and auto-bootstrap logic for ML severity scoring."""

from __future__ import annotations

import numpy as np


def generate_training_data(seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic labeled training data from the 8 scenario archetypes.

    Each archetype is augmented with realistic noise variations to produce
    a balanced dataset (~246 samples) representing enterprise SOC investigations.
    """
    rng = np.random.default_rng(seed)
    samples: list[np.ndarray] = []
    labels: list[int] = []

    # Archetypes: (base_feature_vector, label [0=benign, 1=malicious], n_augmentations)
    archetypes = [
        # ── Malicious scenarios ──
        # 01: Web defacement — scanner + execution + external malicious TI
        (np.array([1, 0.95, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 14, 2, 2, 0, 1, 0.0, 0.0, 0, 0], dtype=np.float64), 1, 25),
        # 02: Brute force + success
        (np.array([1, 0.92, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 33, 1, 1, 3, 1, 0.0, 0.0, 15, 1], dtype=np.float64), 1, 25),
        # 03: Ransomware — C2 + malicious hash
        (np.array([2, 0.99, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 15, 2, 3, 1, 1, 0.0, 0.5, 0, 1], dtype=np.float64), 1, 25),
        # 04: Data exfiltration — after hours + high outbound
        (np.array([1, 0.88, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 11, 1, 2, 1, 1, 0.9, 48.5, 0, 1], dtype=np.float64), 1, 25),
        # 08: Credential stuffing — brute force + multi-user
        (np.array([1, 0.90, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 29, 1, 1, 12, 1, 0.0, 0.0, 10, 2], dtype=np.float64), 1, 25),

        # ── Suspicious scenarios ──
        # 05: Reconnaissance only — no execution, internal
        (np.array([0, 0.0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 29, 1, 10, 0, 0, 0.0, 0.0, 0, 0], dtype=np.float64), 1, 15),
        # 07: Lateral movement — dual-use tool, ambiguous
        (np.array([0, 0.0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 7, 2, 3, 1, 0, 0.0, 0.0, 0, 2], dtype=np.float64), 1, 15),

        # ── Benign scenarios ──
        # 06: Scheduled task — false positive
        (np.array([0, 0.0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 4, 1, 1, 1, 0, 0.0, 0.0, 0, 1], dtype=np.float64), 0, 25),
        # Generic benign: normal traffic, clean TI, no patterns
        (np.array([0, 0.0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 1, 1, 1, 0, 0.0, 0.0, 0, 1], dtype=np.float64), 0, 25),
        # Generic benign: internal scan by security team
        (np.array([0, 0.0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 1, 5, 1, 0, 0.1, 0.0, 0, 0], dtype=np.float64), 0, 15),
        # Generic benign: scheduled backup
        (np.array([0, 0.0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 3, 1, 1, 1, 0, 0.0, 2.0, 0, 0], dtype=np.float64), 0, 15),
    ]

    for base_features, label, n_aug in archetypes:
        samples.append(base_features.copy())
        labels.append(label)

        for _ in range(n_aug):
            noise = rng.normal(0, 0.1, size=base_features.shape)
            augmented = base_features + noise
            # Clamp binary pattern flags
            for idx in range(6, 12):
                augmented[idx] = 1.0 if augmented[idx] > 0.5 else 0.0
            # Clamp non-negative counts
            augmented = np.maximum(augmented, 0.0)
            # Clamp probability features
            augmented[1] = np.clip(augmented[1], 0.0, 1.0)
            augmented[17] = np.clip(augmented[17], 0.0, 1.0)
            samples.append(augmented)
            labels.append(label)

    x = np.array(samples)
    y = np.array(labels)
    return x, y
