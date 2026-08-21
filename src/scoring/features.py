"""Feature engineering for ML-based severity scoring.

Extracts numerical features from investigation evidence (threat intel results,
correlation patterns, log event statistics) into a flat vector suitable for
scikit-learn classifiers.

The feature schema is fixed and documented — adding a feature requires updating
FEATURE_NAMES and the extraction logic together.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from src.models.alert import ThreatIntelResult
from src.tools.correlator import is_external_ip


# Canonical feature order — must match training and inference
FEATURE_NAMES: list[str] = [
    "ti_malicious_count",
    "ti_max_confidence",
    "ti_suspicious_count",
    "pattern_count_critical",
    "pattern_count_medium",
    "pattern_count_low",
    "has_brute_force",
    "has_c2_exfil",
    "has_recon_exec",
    "has_lateral_movement",
    "has_recon_only",
    "has_scheduled_task",
    "event_count",
    "unique_src_ips",
    "unique_dest_ips",
    "unique_users",
    "external_dest_count",
    "off_hours_ratio",
    "total_bytes_out_mb",
    "failed_auth_count",
    "successful_auth_count",
]


def extract_features(
    threat_intel: list[ThreatIntelResult],
    patterns: list[dict[str, Any]],
    log_events: list[dict[str, Any]] | None = None,
) -> np.ndarray:
    """Extract a fixed-length feature vector from investigation evidence.

    Returns a 1D numpy array of shape (len(FEATURE_NAMES),).
    """
    events = log_events or []

    # ── Threat Intel features ──
    malicious = [t for t in threat_intel if t.reputation == "malicious"]
    suspicious = [t for t in threat_intel if t.reputation == "suspicious"]
    ti_malicious_count = float(len(malicious))
    ti_max_confidence = max((t.confidence for t in malicious), default=0.0)
    ti_suspicious_count = float(len(suspicious))

    # ── Pattern features ──
    severity_map = {"critical": 0, "medium": 0, "low": 0}
    pattern_names: set[str] = set()
    for p in patterns:
        sev = p.get("severity", "medium")
        severity_map[sev] = severity_map.get(sev, 0) + 1
        pattern_names.add(p.get("pattern", ""))

    # ── Log event features ──
    unique_src = {e.get("src_ip") for e in events if e.get("src_ip")}
    unique_dst = {e.get("dest_ip") for e in events if e.get("dest_ip")}
    unique_users = {e.get("user") for e in events if e.get("user")}
    external_dests = {ip for ip in unique_dst if is_external_ip(str(ip))}

    off_hours_count = sum(
        1 for e in events if _is_off_hours_str(e.get("timestamp"))
    )
    off_hours_ratio = off_hours_count / len(events) if events else 0.0

    total_bytes_out = sum(
        int(e.get("bytes_sent", 0) or 0) for e in events
    )
    total_bytes_out_mb = total_bytes_out / 1_000_000.0

    failed_auth = sum(1 for e in events if e.get("action") == "login_failed")
    success_auth = sum(1 for e in events if e.get("action") == "login_success")

    feature_vector = np.array([
        ti_malicious_count,
        ti_max_confidence,
        ti_suspicious_count,
        float(severity_map["critical"]),
        float(severity_map["medium"]),
        float(severity_map["low"]),
        float("brute_force_followed_by_success" in pattern_names),
        float("command_and_control_or_exfiltration" in pattern_names),
        float("reconnaissance_followed_by_execution" in pattern_names),
        float("lateral_movement_dual_use_tool" in pattern_names),
        float("reconnaissance_only" in pattern_names),
        float("scheduled_task_triggered_execution" in pattern_names),
        float(len(events)),
        float(len(unique_src)),
        float(len(unique_dst)),
        float(len(unique_users)),
        float(len(external_dests)),
        off_hours_ratio,
        total_bytes_out_mb,
        float(failed_auth),
        float(success_auth),
    ], dtype=np.float64)

    return feature_vector


def _is_off_hours_str(ts: Any) -> bool:
    """Check if timestamp string falls outside business hours (22:00-06:00)."""
    if ts is None:
        return False
    ts_str = str(ts)
    # Fast hour extraction from ISO format: "2024-08-10T22:30:00..."
    try:
        t_idx = ts_str.index("T")
        hour = int(ts_str[t_idx + 1: t_idx + 3])
        return hour >= 22 or hour < 6
    except (ValueError, IndexError):
        return False
