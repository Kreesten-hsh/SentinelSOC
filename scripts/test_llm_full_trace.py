"""Execute full live LLM investigation with qwen2.5:0.5b and print complete trace."""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.models.alert import Alert, Severity


def run_full_llm_investigation() -> None:
    alert = Alert(
        id="ALT-2024-001",
        title="Web Vulnerability Scanner Detected — imreallynotbatman.com",
        description="Suricata IDS detected Acunetix Web Vulnerability Scanner probing web server from external IP 23.22.63.114.",
        timestamp=datetime.now(timezone.utc),
        source="Suricata IDS",
        raw_data={
            "src_ip": "23.22.63.114",
            "dest_ip": "192.168.250.70",
            "dest_port": 80,
            "signature": "ET SCAN Acunetix Web Vulnerability Scanner",
        },
        scenario_id="scenario_01_web_defacement",
    )

    print("=" * 70)
    print("SentinelSOC — Live Agentic LLM Autonomous Investigation Test")
    print(f"Model: ollama/qwen2.5:0.5b | Target Alert: {alert.id}")
    print("=" * 70)

    start_time = time.time()
    agent = SentinelInvestigationAgent(use_llm=True, model_name="ollama/qwen2.5:0.5b")
    
    if agent._llm_agent is None:
        print("ERROR: LLM agent could not be initialized.")
        sys.exit(1)

    print(f"Agent initialized successfully with tools: {list(agent._llm_agent.tools.keys())}")
    print("Beginning autonomous smolagents CodeAgent execution loop...\n")

    try:
        raw_result = agent.investigate_llm(alert)
        duration = time.time() - start_time
        print("\n" + "=" * 70)
        print(f"INVESTIGATION COMPLETE in {duration:.2f} seconds")
        print("=" * 70)
        print("\n=== FINAL RESULT / CONCLUSION RETURNED BY AGENT ===")
        print(raw_result)
        print("=== END FINAL RESULT ===\n")
    except Exception as exc:
        duration = time.time() - start_time
        print(f"\nExecution encountered error after {duration:.2f}s: {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    run_full_llm_investigation()
