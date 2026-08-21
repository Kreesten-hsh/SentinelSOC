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
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.scoring.severity_scorer import SeverityScorer

from src.agent.prompts import INVESTIGATION_SYSTEM_PROMPT
from src.data.log_store import LogStore
from src.models.alert import (
    Alert,
    CorrelationFinding,
    IOC,
    IOCCollection,
    IOCType,
    InvestigationResult,
    InvestigationStep,
    LogEvent,
    RecommendedAction,
    SeverityScore,
    ThreatIntelResult,
    Verdict,
)
from src.tools.correlator import EventCorrelatorTool
from src.tools.ioc_extractor import IOCExtractorTool
from src.tools.log_query import LogQueryTool
from src.tools.threat_intel import ThreatIntelTool

logger = logging.getLogger(__name__)


class SentinelInvestigationAgent:
    """Autonomous SOC tier-2/3 investigation agent."""

    def __init__(
        self,
        log_store: LogStore | None = None,
        threat_intel_path: Path | None = None,
        model_name: str | None = None,
        use_llm: bool = False,
    ) -> None:
        self.log_store = log_store or LogStore(Path(__file__).resolve().parent.parent.parent / "data" / "scenarios")
        self.ioc_tool = IOCExtractorTool()
        self.log_tool = LogQueryTool(log_store=self.log_store)
        self.corr_tool = EventCorrelatorTool(log_store=self.log_store)
        self.ti_tool = ThreatIntelTool(threat_intel_file=threat_intel_path)
        self.severity_scorer = SeverityScorer()

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
                instructions=INVESTIGATION_SYSTEM_PROMPT,
                max_steps=8,
            )
            logger.info("smolagents CodeAgent initialized with model '%s'", self.model_name)
        except Exception as err:
            logger.error("LLM CodeAgent initialization failed: %s", err, exc_info=True)
            self._llm_agent = None

    def investigate_llm(self, alert: Alert) -> str:
        """Execute dynamic autonomous investigation via smolagents CodeAgent and LiteLLM.

        Returns the raw trace / final synthesis text produced by the LLM agent.
        """
        if self._llm_agent is None:
            self._init_llm_agent()
            if self._llm_agent is None:
                raise RuntimeError(
                    f"Failed to initialize LLM CodeAgent with model '{self.model_name}'. "
                    "Ensure Ollama or API credentials are configured."
                )

        prompt = f"""Investigate the following security alert:
Alert ID: {alert.id}
Source: {alert.source}
Title: {alert.title}
Timestamp: {alert.timestamp.isoformat()}
Description: {alert.description}
Raw Data: {json.dumps(alert.raw_data)}

Use your tools to extract IOCs, query logs, correlate events, and check threat intel.
Conclude with a clear verdict (TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS) and recommended action.
"""
        return str(self._llm_agent.run(prompt))

    def investigate(self, alert: Alert) -> InvestigationResult:
        """Execute a complete, structured investigation on a raw alert."""
        started_at = datetime.now(UTC)
        steps: list[InvestigationStep] = []
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

        action_net = (
            f"Query network and perimeter telemetry for source IP '{query_src_ip}'"
            if query_src_ip
            else "Query network and perimeter telemetry for relevant network traffic"
        )

        steps.append(InvestigationStep(
            step_number=2,
            action=action_net,
            reasoning="Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing",
            tool_used=self.log_tool.name,
            query=f"src_ip={query_src_ip or '*'}, scenario_id={scenario_ref or '*'}",
            result_summary=f"Identified {len(matched_events)} matching network/IDS telemetry events.",
            events_found=len(matched_events),
            timestamp=datetime.now(UTC),
        ))

        # ── Step 3: Query Authentication & Endpoint Logs ──
        query_user = user_val or (ioc_collection.users[0].value if ioc_collection.users else None)
        query_host = host_val or (ioc_collection.domains[0].value if ioc_collection.domains else None)

        auth_logs_raw = self.log_tool.forward(
            user=query_user,
            host=query_host,
            scenario_id=scenario_ref,
            max_results=50,
        )
        auth_data = json.loads(auth_logs_raw)
        host_events = auth_data.get("events", [])

        target_entities = []
        if query_user:
            target_entities.append(f"user '{query_user}'")
        if query_host:
            target_entities.append(f"host '{query_host}'")
        target_str = " and ".join(target_entities) if target_entities else "all active identities and hosts"

        steps.append(InvestigationStep(
            step_number=3,
            action=f"Query authentication and endpoint activity for {target_str}",
            reasoning="Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes",
            tool_used=self.log_tool.name,
            query=f"user={query_user or '*'}, host={query_host or '*'}, scenario_id={scenario_ref or '*'}",
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
            query=f"scenario_id={scenario_ref or '*'}, target_ip={query_src_ip or '*'}",
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

        # ── Step 6: Severity Scoring ──
        # Collect log events as dicts for the scorer
        all_logs: list[LogEvent] = []
        if alert.scenario_id:
            all_logs = self.log_store.query_by_scenario(alert.scenario_id)
        else:
            # Gather from store using available observables
            gathered_events: list[LogEvent] = []
            if query_src_ip:
                gathered_events.extend(self.log_store.query_by_src_ip(query_src_ip))
            if query_user:
                gathered_events.extend(self.log_store.query_by_user(query_user))
            if query_host:
                gathered_events.extend(self.log_store.query_by_host(query_host))
            seen_ids: set[str] = set()
            for evt in gathered_events:
                eid = str(evt.id)
                if eid not in seen_ids:
                    seen_ids.add(eid)
                    all_logs.append(evt)

        log_event_dicts = [
            {
                "timestamp": e.timestamp.isoformat(),
                "src_ip": e.src_ip,
                "dest_ip": e.dest_ip,
                "user": e.user,
                "host": e.host,
                "action": e.action,
                "bytes_sent": e.metadata.get("bytes_sent", 0),
            }
            for e in all_logs
        ]

        severity_result = self.severity_scorer.score(
            threat_intel=threat_intel_results,
            patterns=patterns,
            log_events=log_event_dicts,
        )

        steps.append(InvestigationStep(
            step_number=6,
            action="Compute combined severity score (rules + ML)",
            reasoning="Combine explicit rule-based scoring with ML binary classification to produce calibrated severity",
            tool_used="score_severity",
            query=f"rules={len(severity_result.rules_triggered)} triggered, ml_confidence={severity_result.ml_confidence:.2f}",
            result_summary=f"Score: {severity_result.final_score:.1f}/100 | Severity: {severity_result.severity.value.upper()} | Rules: {severity_result.rules_triggered}",
            events_found=1,
            timestamp=datetime.now(UTC),
        ))

        # ── Step 7: Formulate Analytical Verdict & Recommendation ──
        verdict, action = self._synthesize_verdict(
            threat_intel=threat_intel_results,
            patterns=patterns,
        )

        steps.append(InvestigationStep(
            step_number=7,
            action="Synthesize final investigation verdict and containment action",
            reasoning="Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict",
            tool_used="investigation_synthesis",
            query="Analytical evaluation",
            result_summary=f"Verdict: {verdict.value.upper()} | Recommended Action: {action.value.upper()}",
            events_found=1,
            timestamp=datetime.now(UTC),
        ))

        completed_at = datetime.now(UTC)

        return InvestigationResult(
            alert_id=alert.id,
            iocs=ioc_collection,
            steps=steps,
            log_events=all_logs,
            correlations=correlations,
            threat_intel=threat_intel_results,
            severity_score=severity_result,
            verdict=verdict,
            recommended_action=action,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _synthesize_verdict(
        self,
        threat_intel: list[ThreatIntelResult],
        patterns: list[dict[str, Any]],
    ) -> tuple[Verdict, RecommendedAction]:
        """Evidence-grounded analytical decision engine.

        Strictly decoupled from alert metadata/titles/descriptions/scenario_ids.
        Decisions are synthesized exclusively from correlation patterns and threat intelligence.
        """
        pattern_names = {p.get("pattern") for p in patterns}

        # 1. Confirmed Threat -> TRUE_POSITIVE / CONTAIN
        # Triggered if at least one IOC has malicious reputation with confidence >= 0.85,
        # OR if any critical multi-stage attack pattern is confirmed.
        has_malicious_ti = any(
            t.reputation == "malicious" and t.confidence >= 0.85
            for t in threat_intel
        )
        critical_patterns = {
            "brute_force_followed_by_success",
            "command_and_control_or_exfiltration",
            "reconnaissance_followed_by_execution",
        }
        has_critical_pattern = bool(pattern_names & critical_patterns)

        if has_malicious_ti or has_critical_pattern:
            return Verdict.TRUE_POSITIVE, RecommendedAction.CONTAIN

        # 2. Ambiguous Lateral Movement -> SUSPICIOUS / ESCALATE
        if "lateral_movement_dual_use_tool" in pattern_names:
            return Verdict.SUSPICIOUS, RecommendedAction.ESCALATE

        # 3. Reconnaissance Only -> SUSPICIOUS / MONITOR
        if "reconnaissance_only" in pattern_names:
            return Verdict.SUSPICIOUS, RecommendedAction.MONITOR

        # 4. Scheduled Routine Activity Without Malicious Signals -> FALSE_POSITIVE / IGNORE
        if "scheduled_task_triggered_execution" in pattern_names:
            return Verdict.FALSE_POSITIVE, RecommendedAction.IGNORE

        # 5. Default Fallback
        if patterns:
            return Verdict.SUSPICIOUS, RecommendedAction.MONITOR

        return Verdict.FALSE_POSITIVE, RecommendedAction.IGNORE
