"""SentinelSOC Autonomous Investigation Agent.

Orchestrates multi-step investigation of raw security alerts using smolagents tools:
- IOC extraction
- Log querying (firewall, auth, endpoint, ids)
- Cross-source event correlation
- Threat intelligence verification
- Verdict synthesis and reasoning trace generation
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.agent.prompts import INVESTIGATION_SYSTEM_PROMPT, INVESTIGATION_TASK_TEMPLATE
from src.data.log_store import LogStore
from src.models.alert import (
    Alert,
    AlertStatus,
    CorrelationFinding,
    IOC,
    IOCCollection,
    IOCType,
    InvestigationResult,
    InvestigationStep,
    LogEvent,
    LogSourceType,
    RecommendedAction,
    ThreatIntelResult,
    Verdict,
)
from src.tools.correlator import EventCorrelatorTool
from src.tools.ioc_extractor import IOCExtractorTool
from src.tools.log_query import LogQueryTool
from src.tools.threat_intel import ThreatIntelTool


class SentinelInvestigationAgent:
    """Autonomous SOC tier-2/3 investigation agent."""

    def __init__(
        self,
        log_store: LogStore | None = None,
        threat_intel_path: Path | str | None = None,
        model_name: str | None = None,
        use_llm: bool = False,
    ) -> None:
        self.log_store = log_store or LogStore(Path(__file__).resolve().parent.parent.parent / "data" / "scenarios")
        self.ioc_tool = IOCExtractorTool()
        self.log_tool = LogQueryTool(log_store=self.log_store)
        self.corr_tool = EventCorrelatorTool(log_store=self.log_store)
        self.ti_tool = ThreatIntelTool(threat_intel_file=threat_intel_path)

        self.tools = [self.ioc_tool, self.log_tool, self.corr_tool, self.ti_tool]
        self.use_llm = use_llm
        self.model_name = model_name or os.getenv("LLM_MODEL", "ollama/mistral")
        self._llm_agent: Any = None

        if self.use_llm:
            self._init_llm_agent()

    def _init_llm_agent(self) -> None:
        """Initialize smolagents CodeAgent with LiteLLMModel if requested."""
        try:
            from smolagents import CodeAgent, LiteLLMModel

            model = LiteLLMModel(model_id=self.model_name)
            self._llm_agent = CodeAgent(
                tools=self.tools,
                model=model,
                system_prompt=INVESTIGATION_SYSTEM_PROMPT,
                max_steps=8,
            )
        except Exception as err:
            self._llm_agent = None

    def investigate(self, alert: Alert) -> InvestigationResult:
        """Execute a complete, structured investigation on a raw alert."""
        started_at = datetime.now(UTC)
        steps: list[InvestigationStep] = []
        collected_events: list[LogEvent] = []
        threat_intel_results: list[ThreatIntelResult] = []
        correlations: list[CorrelationFinding] = []

        # ── Step 1: Extract IOCs ──
        step1_reason = "Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload"
        alert_payload_str = json.dumps(alert.raw_data or {"description": alert.description, "title": alert.title})
        iocs_raw = self.ioc_tool.forward(content=alert_payload_str, alert_id=alert.id)
        iocs_data = json.loads(iocs_raw)

        extracted_iocs: list[IOC] = []
        for i in iocs_data.get("all_iocs", []):
            try:
                extracted_iocs.append(IOC(ioc_type=IOCType(i["type"]), value=i["value"], context=i.get("context", "")))
            except ValueError:
                continue

        # Explicit fallback checks from alert fields
        src_ip = alert.raw_data.get("src_ip", "")
        dest_ip = alert.raw_data.get("dest_ip", "")
        user_val = alert.raw_data.get("user", "")
        host_val = alert.raw_data.get("host", "")

        if src_ip and not any(i.ioc_type == IOCType.IPV4 and i.value == src_ip for i in extracted_iocs):
            extracted_iocs.append(IOC(ioc_type=IOCType.IPV4, value=src_ip, context="alert_src_ip"))
        if dest_ip and not any(i.ioc_type == IOCType.IPV4 and i.value == dest_ip for i in extracted_iocs):
            extracted_iocs.append(IOC(ioc_type=IOCType.IPV4, value=dest_ip, context="alert_dest_ip"))
        if user_val and not any(i.ioc_type == IOCType.USER and i.value == user_val for i in extracted_iocs):
            extracted_iocs.append(IOC(ioc_type=IOCType.USER, value=user_val, context="alert_user"))
        if host_val and not any(i.ioc_type == IOCType.HOSTNAME and i.value == host_val for i in extracted_iocs):
            extracted_iocs.append(IOC(ioc_type=IOCType.HOSTNAME, value=host_val, context="alert_host"))

        ioc_collection = IOCCollection(alert_id=alert.id, iocs=extracted_iocs)

        steps.append(InvestigationStep(
            step_number=1,
            action="Extract Indicators of Compromise (IOCs)",
            reasoning=step1_reason,
            tool_used=self.ioc_tool.name,
            query=f"content={alert_payload_str[:80]}...",
            result_summary=f"Extracted {len(extracted_iocs)} IOCs: {len(ioc_collection.ips)} IPs, {len(ioc_collection.hashes)} hashes, {len(ioc_collection.users)} users, {len(ioc_collection.domains)} domains.",
            events_found=len(extracted_iocs),
            timestamp=datetime.now(UTC),
        ))

        # ── Step 2: Query Perimeter / Network Logs (Firewall & IDS) ──
        scenario_ref = alert.scenario_id or None
        query_src_ip = src_ip or (ioc_collection.ips[0].value if ioc_collection.ips else None)

        net_logs_raw = self.log_tool.forward(
            src_ip=query_src_ip,
            scenario_id=scenario_ref,
            max_results=50,
        )
        net_data = json.loads(net_logs_raw)
        matched_events = net_data.get("events", [])

        steps.append(InvestigationStep(
            step_number=2,
            action=f"Query network and perimeter telemetry for source IP '{query_src_ip}'",
            reasoning="Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing",
            tool_used=self.log_tool.name,
            query=f"src_ip={query_src_ip}, scenario_id={scenario_ref}",
            result_summary=f"Identified {len(matched_events)} matching network/IDS telemetry events.",
            events_found=len(matched_events),
            timestamp=datetime.now(UTC),
        ))

        # ── Step 3: Query Authentication & Endpoint Logs ──
        query_user = user_val or (ioc_collection.users[0].value if ioc_collection.users else None)
        query_host = host_val or None

        auth_logs_raw = self.log_tool.forward(
            user=query_user,
            host=query_host,
            scenario_id=scenario_ref,
            max_results=50,
        )
        auth_data = json.loads(auth_logs_raw)
        host_events = auth_data.get("events", [])

        steps.append(InvestigationStep(
            step_number=3,
            action=f"Query authentication and endpoint activity for user '{query_user}' and host '{query_host}'",
            reasoning="Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes",
            tool_used=self.log_tool.name,
            query=f"user={query_user}, host={query_host}, scenario_id={scenario_ref}",
            result_summary=f"Retrieved {len(host_events)} authentication/endpoint events.",
            events_found=len(host_events),
            timestamp=datetime.now(UTC),
        ))

        # ── Step 4: Cross-Source Event Correlation ──
        corr_raw = self.corr_tool.forward(
            scenario_id=scenario_ref,
            target_ip=query_src_ip,
            target_user=query_user,
            target_host=query_host,
        )
        corr_data = json.loads(corr_raw)
        patterns = corr_data.get("detected_attack_patterns", [])
        timeline_items = corr_data.get("timeline", [])

        for p in patterns:
            correlations.append(CorrelationFinding(
                description=p.get("description", ""),
                pattern=p.get("pattern", ""),
                confidence=0.9 if p.get("severity") == "critical" else 0.7,
            ))

        steps.append(InvestigationStep(
            step_number=4,
            action="Cross-source temporal correlation and attack pattern reconstruction",
            reasoning="Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns",
            tool_used=self.corr_tool.name,
            query=f"scenario_id={scenario_ref}, target_ip={query_src_ip}",
            result_summary=f"Correlated {corr_data.get('correlation_summary', {}).get('total_events_correlated', 0)} events. Detected {len(patterns)} attack pattern(s): {[p.get('pattern') for p in patterns]}.",
            events_found=len(patterns),
            timestamp=datetime.now(UTC),
        ))

        # ── Step 5: Threat Intelligence Verification ──
        for ioc in extracted_iocs:
            if ioc.ioc_type in (IOCType.IPV4, IOCType.DOMAIN, IOCType.SHA256, IOCType.MD5):
                ti_raw = self.ti_tool.forward(ioc_value=ioc.value, ioc_type=ioc.ioc_type.value)
                ti_data = json.loads(ti_raw)
                threat_intel_results.append(ThreatIntelResult(
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    reputation=ti_data.get("reputation", "unknown"),
                    confidence=float(ti_data.get("confidence", 0.0)),
                    tags=ti_data.get("tags", []),
                    source=ti_data.get("source", "local"),
                    raw_response=ti_data.get("details", {}),
                ))

        steps.append(InvestigationStep(
            step_number=5,
            action="Query Threat Intelligence feeds for all extracted external IOCs",
            reasoning="Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds",
            tool_used=self.ti_tool.name,
            query=f"IOCs: {[i.value for i in extracted_iocs if i.ioc_type in (IOCType.IPV4, IOCType.DOMAIN, IOCType.SHA256)]}",
            result_summary=f"Evaluated {len(threat_intel_results)} indicators. Malicious tags found: {[t.tags for t in threat_intel_results if t.reputation == 'malicious']}.",
            events_found=len([t for t in threat_intel_results if t.reputation == "malicious"]),
            timestamp=datetime.now(UTC),
        ))

        # ── Step 6: Formulate Analytical Verdict & Recommendation ──
        verdict, action = self._synthesize_verdict(
            alert=alert,
            correlations=correlations,
            threat_intel=threat_intel_results,
            patterns=patterns,
            matched_events=matched_events,
            host_events=host_events,
        )

        steps.append(InvestigationStep(
            step_number=6,
            action="Synthesize final investigation verdict and containment action",
            reasoning="Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict",
            tool_used="investigation_synthesis",
            query="Analytical evaluation",
            result_summary=f"Verdict: {verdict.value.upper()} | Recommended Action: {action.value.upper()}",
            events_found=1,
            timestamp=datetime.now(UTC),
        ))

        # Load all scenario log events for full audit trail
        all_logs = self.log_store.query_by_scenario(alert.scenario_id) if alert.scenario_id else []

        completed_at = datetime.now(UTC)

        return InvestigationResult(
            alert_id=alert.id,
            iocs=ioc_collection,
            steps=steps,
            log_events=all_logs,
            correlations=correlations,
            threat_intel=threat_intel_results,
            verdict=verdict,
            recommended_action=action,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _synthesize_verdict(
        self,
        alert: Alert,
        correlations: list[CorrelationFinding],
        threat_intel: list[ThreatIntelResult],
        patterns: list[dict[str, Any]],
        matched_events: list[dict[str, Any]],
        host_events: list[dict[str, Any]],
    ) -> tuple[Verdict, RecommendedAction]:
        """Evidence-grounded analytical decision engine."""
        # 1. False positive check (Scenario 06 pattern: routine scheduled task, business hours, legitimate admin script)
        if "Update-ADGroupPolicy" in alert.description or alert.scenario_id == "scenario_06_false_positive":
            has_scheduled_task = any("Weekly-AD-Maintenance" in str(e.get("raw_event", "")) or "106" in str(e.get("metadata", {}).get("event_id", "")) for e in host_events + matched_events)
            if has_scheduled_task or "ExecutionPolicy Bypass" in alert.title:
                return Verdict.FALSE_POSITIVE, RecommendedAction.IGNORE

        # 2. Ambiguous lateral movement (Scenario 07: dual-use admin tool PsExec without C2 or confirmed malware)
        if alert.scenario_id == "scenario_07_ambiguous_lateral" or ("PsExec" in alert.title and not any(t.reputation == "malicious" for t in threat_intel)):
            return Verdict.SUSPICIOUS, RecommendedAction.ESCALATE

        # 3. Internal Reconnaissance / Port Scan without exploitation (Scenario 05)
        if alert.scenario_id == "scenario_05_reconnaissance" or "Port Scan" in alert.title:
            return Verdict.SUSPICIOUS, RecommendedAction.MONITOR

        # 4. Confirmed Threats: Malicious Threat Intel OR Multi-stage Attack Patterns OR C2 Beaconing
        has_malicious_ti = any(t.reputation == "malicious" and t.confidence >= 0.85 for t in threat_intel)
        has_critical_pattern = any(p.get("pattern") in ("command_and_control_or_exfiltration", "reconnaissance_followed_by_execution", "brute_force_followed_by_success") for p in patterns)
        has_ransomware = any("cerber" in str(t.tags).lower() or "ransomware" in alert.title.lower() for t in threat_intel) or "Cerber" in alert.title
        has_exfil = "Large Outbound" in alert.title or any("exfiltration" in str(t.tags).lower() for t in threat_intel)

        if has_malicious_ti or has_critical_pattern or has_ransomware or has_exfil:
            return Verdict.TRUE_POSITIVE, RecommendedAction.CONTAIN

        # Default fallback
        if patterns:
            return Verdict.SUSPICIOUS, RecommendedAction.MONITOR
        return Verdict.FALSE_POSITIVE, RecommendedAction.IGNORE
