#!/usr/bin/env python3
"""Run SentinelSOC investigation agent on all 8 sample alerts and export structured traces."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.data.log_store import LogStore
from src.models.alert import Alert


def run_all_investigations() -> None:
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data"
    alerts_file = data_dir / "alerts" / "sample_alerts.json"
    output_dir = data_dir / "investigations"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SentinelSOC — Autonomous SOC Alert Investigation Engine")
    print(f"Timestamp: {datetime.now(UTC).isoformat()}")
    print("=" * 80)

    log_store = LogStore(data_dir / "scenarios")
    agent = SentinelInvestigationAgent(
        log_store=log_store,
        threat_intel_path=data_dir / "threat_intel" / "known_iocs.json",
        use_llm=False,
    )

    with alerts_file.open("r", encoding="utf-8") as fh:
        raw_alerts = json.load(fh)
    alerts = [Alert.model_validate(a) for a in raw_alerts]

    print(f"\nLoaded {len(alerts)} alerts to investigate.\n")

    summary_records = []

    for idx, alert in enumerate(alerts, 1):
        print(f"[{idx}/8] Investigating Alert {alert.id}: {alert.title}")
        result = agent.investigate(alert)

        # Print investigation steps
        for step in result.steps:
            print(f"   Step {step.step_number}: [{step.tool_used}] {step.action}")
            print(f"      Reasoning: {step.reasoning}")
            print(f"      Result: {step.result_summary}")

        verdict_str = result.verdict.value.upper() if result.verdict else "UNKNOWN"
        action_str = result.recommended_action.value.upper() if result.recommended_action else "UNKNOWN"
        print(f"   --> FINAL VERDICT: {verdict_str} | ACTION: {action_str}\n")

        # Export individual investigation JSON
        trace_file = output_dir / f"{alert.id}_investigation.json"
        with trace_file.open("w", encoding="utf-8") as fh:
            fh.write(result.model_dump_json(indent=2))

        summary_records.append({
            "alert_id": alert.id,
            "title": alert.title,
            "scenario": alert.scenario_id,
            "verdict": verdict_str,
            "action": action_str,
            "iocs_extracted": len(result.iocs.iocs),
            "events_correlated": len(result.log_events),
            "trace_file": str(trace_file.relative_to(project_root)),
        })

    # Export summary manifest
    manifest_file = output_dir / "investigations_summary.json"
    with manifest_file.open("w", encoding="utf-8") as fh:
        json.dump({
            "generated_at": datetime.now(UTC).isoformat(),
            "total_alerts": len(alerts),
            "results": summary_records,
        }, fh, indent=2)

    print("=" * 80)
    print(f"Investigation complete. Traces saved to {output_dir}")
    print(f"Summary manifest: {manifest_file}")
    print("=" * 80)


if __name__ == "__main__":
    run_all_investigations()
