"""Generate investigation reports for all 8 scenarios.

Runs each alert through the investigation agent and generates a Markdown
report using the report generator. Reports are saved to data/reports/.

Usage:
    python3 scripts/generate_reports.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.data.log_store import LogStore
from src.models.alert import Alert
from src.reporting.report_generator import ReportGenerator


def main() -> None:
    print("=" * 70)
    print("SentinelSOC — Investigation Report Generation")
    print("=" * 70)

    # Load infrastructure
    log_store = LogStore(PROJECT_ROOT / "data" / "scenarios")
    agent = SentinelInvestigationAgent(
        log_store=log_store,
        threat_intel_path=PROJECT_ROOT / "data" / "threat_intel" / "known_iocs.json",
        use_llm=False,
    )
    report_gen = ReportGenerator()

    # Load alerts
    alerts_path = PROJECT_ROOT / "data" / "alerts" / "sample_alerts.json"
    with alerts_path.open("r", encoding="utf-8") as fh:
        raw_alerts = json.load(fh)
    alerts = [Alert.model_validate(a) for a in raw_alerts]

    # Output directory
    reports_dir = PROJECT_ROOT / "data" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    for i, alert in enumerate(alerts, 1):
        print(f"\n[{i}/{len(alerts)}] Generating report for {alert.id}: {alert.title}")

        # Investigate
        result = agent.investigate(alert)

        # Generate report
        report = report_gen.generate(alert=alert, result=result)

        # Save markdown
        md_path = reports_dir / f"{alert.id}_report.md"
        md_path.write_text(report.markdown, encoding="utf-8")
        print(f"   Verdict: {report.verdict.upper()} | Severity: {report.severity_assessment.get('severity', 'N/A').upper()}")
        print(f"   Report saved: {md_path}")

        # Save structured JSON
        json_path = reports_dir / f"{alert.id}_report.json"
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    print(f"\n{'=' * 70}")
    print(f"All {len(alerts)} reports generated in {reports_dir}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
