"""Tool for multi-source event correlation and attack chain reconstruction."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from smolagents import Tool

from src.data.log_store import LogStore
from src.models.alert import LogEvent, LogSourceType


class EventCorrelatorTool(Tool):
    """smolagents Tool to discover cross-source correlations and construct chronological attack chains."""

    name = "correlate_events"
    description = (
        "Correlates security events across firewall, authentication, endpoint, and IDS sources. "
        "Identifies temporal clusters, causal chains (e.g. failed auth -> success -> command execution), "
        "and links related IP addresses, usernames, and hostnames."
    )
    inputs = {
        "scenario_id": {
            "type": "string",
            "description": "Scenario ID to correlate events for.",
            "nullable": True,
        },
        "target_ip": {
            "type": "string",
            "description": "Primary IP address to center the correlation on.",
            "nullable": True,
        },
        "target_user": {
            "type": "string",
            "description": "Primary username to track across hosts.",
            "nullable": True,
        },
        "target_host": {
            "type": "string",
            "description": "Primary host to analyze for multi-stage activity.",
            "nullable": True,
        },
    }
    output_type = "string"

    def __init__(self, log_store: LogStore | None = None, scenarios_dir: Path | str | None = None) -> None:
        super().__init__()
        if log_store is not None:
            self.store = log_store
        else:
            p = Path(scenarios_dir) if scenarios_dir else Path(__file__).resolve().parent.parent.parent / "data" / "scenarios"
            self.store = LogStore(p)

    def forward(
        self,
        scenario_id: str | None = None,
        target_ip: str | None = None,
        target_user: str | None = None,
        target_host: str | None = None,
    ) -> str:
        events: list[LogEvent] = []
        if scenario_id:
            events = self.store.query_by_scenario(scenario_id)
        else:
            # Gather relevant events
            gathered: list[LogEvent] = []
            if target_ip:
                gathered.extend(self.store.query_by_src_ip(target_ip))
                gathered.extend(self.store.query_by_dest_ip(target_ip))
            if target_user:
                gathered.extend(self.store.query_by_user(target_user))
            if target_host:
                gathered.extend(self.store.query_by_host(target_host))

            # Deduplicate by ID
            seen_ids = set()
            for e in gathered:
                if e.id not in seen_ids:
                    seen_ids.add(e.id)
                    events.append(e)

        events = sorted(events, key=lambda e: e.timestamp)

        if not events:
            return json.dumps({
                "status": "no_events_found",
                "message": "No events found matching the specified correlation criteria.",
                "correlation_chains": [],
            })

        # Discover involved entities
        sources_seen = {e.source_type.value for e in events}
        involved_ips = {e.src_ip for e in events if e.src_ip} | {e.dest_ip for e in events if e.dest_ip}
        involved_users = {e.user for e in events if e.user}
        involved_hosts = {e.host for e in events if e.host}

        # Analyze attack patterns
        detected_patterns: list[dict[str, Any]] = []

        # Pattern 1: Brute force then logon
        failed_logins = [e for e in events if e.action == "login_failed"]
        successful_logins = [e for e in events if e.action == "login_success"]
        if len(failed_logins) >= 3 and len(successful_logins) >= 1:
            first_fail = failed_logins[0].timestamp
            last_fail = failed_logins[-1].timestamp
            success_after = [s for s in successful_logins if s.timestamp >= last_fail]
            if success_after:
                detected_patterns.append({
                    "pattern": "brute_force_followed_by_success",
                    "severity": "high",
                    "description": f"{len(failed_logins)} failed authentications followed by successful login for user '{success_after[0].user}' from {success_after[0].src_ip}",
                    "failed_attempts": len(failed_logins),
                    "success_timestamp": success_after[0].timestamp.isoformat(),
                })

        # Pattern 2: Scan then Web/Shell Exploitation
        scan_events = [e for e in events if "scan" in e.action.lower() or "scan" in str(e.metadata.get("category", "")).lower() or "scan" in str(e.metadata.get("signature", "")).lower()]
        proc_events = [e for e in events if e.action == "process_create" or e.source_type == LogSourceType.ENDPOINT]
        if scan_events and proc_events:
            detected_patterns.append({
                "pattern": "reconnaissance_followed_by_execution",
                "severity": "critical",
                "description": f"Vulnerability scanning detected followed by process execution ({len(proc_events)} endpoint events observed)",
                "recon_count": len(scan_events),
                "endpoint_event_count": len(proc_events),
            })

        # Pattern 3: Process Execution then C2/Exfil Outbound
        fw_outbound = [e for e in events if e.source_type == LogSourceType.FIREWALL and e.metadata.get("bytes_sent", 0) > 1000]
        c2_alerts = [e for e in events if "malware" in str(e.metadata.get("signature", "")).lower() or "cnc" in str(e.metadata.get("signature", "")).lower() or "policy" in str(e.metadata.get("signature", "")).lower()]
        if (proc_events or scan_events) and (fw_outbound or c2_alerts):
            detected_patterns.append({
                "pattern": "command_and_control_or_exfiltration",
                "severity": "critical",
                "description": "Endpoint activity directly correlates with outbound network communication/IDS alert",
                "outbound_events": len(fw_outbound),
                "ids_alerts": len(c2_alerts),
            })

        # Timeline generation (condensed)
        timeline: list[dict[str, Any]] = []
        for e in events:
            timeline.append({
                "timestamp": e.timestamp.isoformat(),
                "source": e.source_type.value,
                "action": e.action,
                "entity_context": f"{e.src_ip}->{e.dest_ip}" if e.src_ip and e.dest_ip else e.user or e.host,
                "summary": e.raw_event[:120] if len(e.raw_event) > 120 else e.raw_event,
            })

        return json.dumps({
            "correlation_summary": {
                "total_events_correlated": len(events),
                "time_span_seconds": int((events[-1].timestamp - events[0].timestamp).total_seconds()) if len(events) > 1 else 0,
                "log_sources_involved": list(sources_seen),
                "unique_ips": list(involved_ips),
                "unique_users": list(involved_users),
                "unique_hosts": list(involved_hosts),
            },
            "detected_attack_patterns": detected_patterns,
            "timeline": timeline,
        }, indent=2)
