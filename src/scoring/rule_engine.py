"""Explicit rule-based severity scoring engine.

Each rule encodes a SOC analyst heuristic: a condition over investigation evidence
and the weight it contributes to the final severity score. Rules are transparent,
auditable, and deterministic — no ML involved.

Score normalization: raw weighted sum is clamped to [0, 100].
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.models.alert import (
    CorrelationFinding,
    IOCType,
    ThreatIntelResult,
)
from src.tools.correlator import is_external_ip


# ──────────────── Rule Definitions ────────────────


@dataclass(frozen=True)
class ScoringRule:
    """A single auditable severity scoring rule."""
    name: str
    description: str
    weight: float  # Points added (positive) or subtracted (negative)
    category: str  # grouping: 'threat_intel', 'correlation', 'temporal', 'network'


@dataclass
class RuleMatch:
    """Evidence that a specific rule was triggered."""
    rule: ScoringRule
    evidence: str
    matched_at: datetime = field(default_factory=lambda: datetime.now())


# Canonical rule set — order does not matter, all matching rules accumulate
RULES: list[ScoringRule] = [
    # ── Threat Intel ──
    ScoringRule(
        name="ti_malicious_high_confidence",
        description="IOC flagged malicious with confidence >= 0.85 in threat intel",
        weight=40.0,
        category="threat_intel",
    ),
    ScoringRule(
        name="ti_malicious_moderate_confidence",
        description="IOC flagged malicious with confidence 0.50-0.84",
        weight=20.0,
        category="threat_intel",
    ),
    ScoringRule(
        name="ti_suspicious",
        description="IOC flagged suspicious in threat intel",
        weight=10.0,
        category="threat_intel",
    ),

    # ── Correlation patterns ──
    ScoringRule(
        name="pattern_brute_force_success",
        description="Brute force with subsequent successful authentication detected",
        weight=35.0,
        category="correlation",
    ),
    ScoringRule(
        name="pattern_c2_exfiltration",
        description="Command-and-control or data exfiltration to external IP",
        weight=40.0,
        category="correlation",
    ),
    ScoringRule(
        name="pattern_recon_then_execution",
        description="Reconnaissance scanning followed by endpoint execution",
        weight=35.0,
        category="correlation",
    ),
    ScoringRule(
        name="pattern_lateral_movement",
        description="Dual-use admin tool with network logons across multiple hosts",
        weight=20.0,
        category="correlation",
    ),
    ScoringRule(
        name="pattern_recon_only",
        description="Network scanning without subsequent execution",
        weight=10.0,
        category="correlation",
    ),
    ScoringRule(
        name="pattern_scheduled_task",
        description="Process execution triggered by scheduled task (benign indicator)",
        weight=-15.0,
        category="correlation",
    ),

    # ── Temporal ──
    ScoringRule(
        name="after_hours_activity",
        description="Primary activity occurred outside business hours (22:00-06:00)",
        weight=15.0,
        category="temporal",
    ),

    # ── Network ──
    ScoringRule(
        name="external_dest_ip",
        description="Communication with at least one external (publicly routable) IP",
        weight=10.0,
        category="network",
    ),
    ScoringRule(
        name="high_volume_outbound",
        description="Large outbound data transfer detected (> 10MB)",
        weight=15.0,
        category="network",
    ),

    # ── Mitigating ──
    ScoringRule(
        name="all_internal_traffic",
        description="All observed network traffic is internal — no external communication",
        weight=-20.0,
        category="network",
    ),
    ScoringRule(
        name="clean_threat_intel",
        description="All checked IOCs returned clean reputation",
        weight=-10.0,
        category="threat_intel",
    ),
]

RULES_BY_NAME: dict[str, ScoringRule] = {r.name: r for r in RULES}

_RULE_INDEX: dict[str, ScoringRule] = {r.name: r for r in RULES}


# ──────────────── Rule Engine ────────────────


class RuleEngine:
    """Evaluates investigation evidence against the canonical rule set.

    Returns a list of matched rules and a raw severity score [0, 100].
    """

    def evaluate(
        self,
        threat_intel: list[ThreatIntelResult],
        patterns: list[dict[str, Any]],
        log_events: list[dict[str, Any]] | None = None,
    ) -> tuple[float, list[RuleMatch]]:
        """Score investigation evidence against all rules.

        Returns (raw_score_clamped_0_100, list_of_matched_rules).
        """
        matches: list[RuleMatch] = []

        # ── Threat Intel rules ──
        malicious_high = [t for t in threat_intel if t.reputation == "malicious" and t.confidence >= 0.85]
        malicious_mod = [t for t in threat_intel if t.reputation == "malicious" and 0.50 <= t.confidence < 0.85]
        suspicious_ti = [t for t in threat_intel if t.reputation == "suspicious"]
        clean_only = all(t.reputation == "clean" for t in threat_intel) if threat_intel else False

        if malicious_high:
            matches.append(RuleMatch(
                rule=_RULE_INDEX["ti_malicious_high_confidence"],
                evidence=f"{len(malicious_high)} IOC(s) malicious ≥0.85: {[t.ioc_value for t in malicious_high]}",
            ))
        if malicious_mod:
            matches.append(RuleMatch(
                rule=_RULE_INDEX["ti_malicious_moderate_confidence"],
                evidence=f"{len(malicious_mod)} IOC(s) malicious 0.50-0.84: {[t.ioc_value for t in malicious_mod]}",
            ))
        if suspicious_ti:
            matches.append(RuleMatch(
                rule=_RULE_INDEX["ti_suspicious"],
                evidence=f"{len(suspicious_ti)} IOC(s) suspicious: {[t.ioc_value for t in suspicious_ti]}",
            ))
        if clean_only and not malicious_high and not malicious_mod and not suspicious_ti:
            matches.append(RuleMatch(
                rule=_RULE_INDEX["clean_threat_intel"],
                evidence="All checked IOCs returned clean reputation",
            ))

        # ── Correlation pattern rules ──
        pattern_names = {p.get("pattern", "") for p in patterns}
        pattern_rule_map: dict[str, str] = {
            "brute_force_followed_by_success": "pattern_brute_force_success",
            "command_and_control_or_exfiltration": "pattern_c2_exfiltration",
            "reconnaissance_followed_by_execution": "pattern_recon_then_execution",
            "lateral_movement_dual_use_tool": "pattern_lateral_movement",
            "reconnaissance_only": "pattern_recon_only",
            "scheduled_task_triggered_execution": "pattern_scheduled_task",
        }
        for p_name, rule_name in pattern_rule_map.items():
            if p_name in pattern_names:
                pattern_detail = next((p for p in patterns if p.get("pattern") == p_name), {})
                matches.append(RuleMatch(
                    rule=_RULE_INDEX[rule_name],
                    evidence=pattern_detail.get("description", p_name),
                ))

        # ── Temporal rules ──
        if log_events:
            off_hours = [
                e for e in log_events
                if _is_off_hours(e.get("timestamp"))
            ]
            if len(off_hours) > len(log_events) * 0.5:
                matches.append(RuleMatch(
                    rule=_RULE_INDEX["after_hours_activity"],
                    evidence=f"{len(off_hours)}/{len(log_events)} events occurred outside business hours",
                ))

        # ── Network rules ──
        if log_events:
            external_dests = {
                e.get("dest_ip")
                for e in log_events
                if e.get("dest_ip") and is_external_ip(str(e.get("dest_ip", "")))
            }
            if external_dests:
                matches.append(RuleMatch(
                    rule=_RULE_INDEX["external_dest_ip"],
                    evidence=f"External destinations: {list(external_dests)[:5]}",
                ))
            elif log_events:
                matches.append(RuleMatch(
                    rule=_RULE_INDEX["all_internal_traffic"],
                    evidence="No external IP destinations observed in correlated events",
                ))

            total_bytes_out = sum(
                int(e.get("bytes_sent", 0) or 0)
                for e in log_events
                if e.get("bytes_sent")
            )
            if total_bytes_out > 10_000_000:  # > 10 MB
                matches.append(RuleMatch(
                    rule=_RULE_INDEX["high_volume_outbound"],
                    evidence=f"Total outbound: {total_bytes_out / 1_000_000:.1f} MB",
                ))

        # ── Compute final score ──
        raw_score = sum(m.rule.weight for m in matches)
        clamped_score = max(0.0, min(100.0, raw_score))

        return clamped_score, matches


def _is_off_hours(ts: Any) -> bool:
    """Return True if timestamp falls between 22:00 and 06:00."""
    if ts is None:
        return False
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return False
    if isinstance(ts, datetime):
        return ts.hour >= 22 or ts.hour < 6
    return False
