"""smolagents Tool wrapping the combined severity scorer.

Exposed to the agent as a callable tool that takes investigation evidence
and returns a structured severity assessment.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from smolagents import Tool

from src.models.alert import IOCType, ThreatIntelResult
from src.scoring.severity_scorer import SeverityScorer


class SeverityScorerTool(Tool):
    """smolagents Tool to compute severity score from investigation evidence."""

    name = "score_severity"
    description = (
        "Computes a combined severity score (0-100) using explicit rules and ML classification. "
        "Accepts threat intelligence results, detected correlation patterns, and optionally raw log events. "
        "Returns severity level (Low/Medium/Critical), score breakdown, and explanation."
    )
    inputs = {
        "threat_intel_json": {
            "type": "string",
            "description": "JSON-encoded list of threat intelligence results (each with ioc_value, reputation, confidence, tags).",
        },
        "patterns_json": {
            "type": "string",
            "description": "JSON-encoded list of detected attack patterns (each with pattern, severity, description).",
        },
        "log_events_json": {
            "type": "string",
            "description": "JSON-encoded list of correlated log events. Optional.",
            "nullable": True,
        },
    }
    output_type = "string"

    def __init__(self, model_path: Path | str | None = None) -> None:
        super().__init__()
        self._scorer = SeverityScorer(model_path=model_path)

    def forward(
        self,
        threat_intel_json: str,
        patterns_json: str,
        log_events_json: str | None = None,
    ) -> str:
        # Parse threat intel
        ti_list: list[ThreatIntelResult] = []
        try:
            raw_ti = json.loads(threat_intel_json)
            for item in raw_ti:
                ti_list.append(ThreatIntelResult(
                    ioc_value=item.get("ioc_value", item.get("ioc", "")),
                    ioc_type=IOCType(item.get("ioc_type", "ipv4")),
                    reputation=item.get("reputation", "unknown"),
                    confidence=float(item.get("confidence", 0.0)),
                    tags=item.get("tags", []),
                    source=item.get("source", "unknown"),
                ))
        except (json.JSONDecodeError, ValueError):
            ti_list = []

        # Parse patterns
        patterns: list[dict[str, Any]] = []
        try:
            patterns = json.loads(patterns_json)
        except json.JSONDecodeError:
            patterns = []

        # Parse log events (optional)
        log_events: list[dict[str, Any]] | None = None
        if log_events_json:
            try:
                log_events = json.loads(log_events_json)
            except json.JSONDecodeError:
                log_events = None

        # Score
        result = self._scorer.score(
            threat_intel=ti_list,
            patterns=patterns,
            log_events=log_events,
        )

        return json.dumps({
            "severity": result.severity.value,
            "final_score": round(result.final_score, 1),
            "rule_score": round(result.rule_score, 1),
            "ml_confidence": round(result.ml_confidence, 4),
            "rules_triggered": result.rules_triggered,
            "ml_top_features": result.ml_features_importance,
            "explanation": result.explanation,
        }, indent=2)
