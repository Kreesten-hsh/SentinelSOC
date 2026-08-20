"""Tool for querying normalized log sources (Firewall, Auth, Endpoint, IDS, Webserver, DNS)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from smolagents import Tool

from src.data.log_store import LogStore
from src.models.alert import LogEvent, LogSourceType


class LogQueryTool(Tool):
    """smolagents Tool to query SIEM/EDR log sources across the environment."""

    name = "query_logs"
    description = (
        "Queries normalized security logs (firewall, auth, endpoint, ids, webserver, dns) "
        "by IP address, username, hostname, source type, or scenario ID. "
        "Returns a chronological list of matching events with raw details."
    )
    inputs = {
        "source_type": {
            "type": "string",
            "description": "Log source category to filter on: 'firewall', 'auth', 'endpoint', 'ids', 'webserver', 'dns', or 'all'.",
            "nullable": True,
        },
        "src_ip": {
            "type": "string",
            "description": "Source IP address to search for in connections or authentication attempts.",
            "nullable": True,
        },
        "dest_ip": {
            "type": "string",
            "description": "Destination IP address to search for in inbound traffic or targeted servers.",
            "nullable": True,
        },
        "user": {
            "type": "string",
            "description": "Username or account identity (e.g. 'admin', 'WAYNE\\bob.smith') to search in auth/process logs.",
            "nullable": True,
        },
        "host": {
            "type": "string",
            "description": "Host/machine name (e.g. 'srv-dc01', 'ws-bobsmith') to search for endpoint activity.",
            "nullable": True,
        },
        "scenario_id": {
            "type": "string",
            "description": "Optional scenario identifier to restrict queries during testing.",
            "nullable": True,
        },
        "max_results": {
            "type": "integer",
            "description": "Maximum number of events to return (default: 25).",
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
        source_type: str | None = None,
        src_ip: str | None = None,
        dest_ip: str | None = None,
        user: str | None = None,
        host: str | None = None,
        scenario_id: str | None = None,
        max_results: int | None = 25,
    ) -> str:
        limit = max_results if max_results and max_results > 0 else 25

        st_enum: LogSourceType | None = None
        if source_type and source_type.lower() != "all":
            try:
                st_enum = LogSourceType(source_type.lower())
            except ValueError:
                st_enum = None

        events: list[LogEvent]
        if scenario_id:
            scenario_events = self.store.query_by_scenario(scenario_id)
            # Filter in-memory
            filtered: list[LogEvent] = []
            for evt in scenario_events:
                if st_enum and evt.source_type != st_enum:
                    continue
                if src_ip and evt.src_ip != src_ip:
                    continue
                if dest_ip and evt.dest_ip != dest_ip:
                    continue
                if user and evt.user.lower() != user.lower():
                    continue
                if host and evt.host.lower() != host.lower():
                    continue
                filtered.append(evt)
            events = filtered
        else:
            # Query the store directly with combined filters
            events = self.store._filter(
                src_ip=src_ip or None,
                dest_ip=dest_ip or None,
                user=user or None,
                host=host or None,
                source_type=st_enum,
            )

        events_subset = events[:limit]
        formatted_events: list[dict[str, Any]] = []
        for evt in events_subset:
            formatted_events.append({
                "timestamp": evt.timestamp.isoformat(),
                "source_type": evt.source_type.value,
                "src_ip": evt.src_ip,
                "dest_ip": evt.dest_ip,
                "src_port": evt.src_port,
                "dest_port": evt.dest_port,
                "user": evt.user,
                "host": evt.host,
                "action": evt.action,
                "raw_event": evt.raw_event,
                "metadata": evt.metadata,
            })

        output = {
            "query_parameters": {
                "source_type": source_type,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "user": user,
                "host": host,
                "scenario_id": scenario_id,
            },
            "total_matches": len(events),
            "returned_count": len(events_subset),
            "events": formatted_events,
        }
        return json.dumps(output, indent=2)
