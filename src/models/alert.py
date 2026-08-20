"""Core data models for SentinelSOC.

Typed Pydantic models representing the domain:
- Alert: raw SIEM alert ingested by the system
- IOC: Indicator of Compromise extracted from an alert
- LogEvent: normalized log entry from any source (firewall, auth, endpoint, IDS)
- InvestigationStep: a single step in the agent's reasoning chain
- InvestigationResult: full investigation output with findings
- InvestigationReport: final structured report for human consumption
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ──────────────────────────── Enums ────────────────────────────


class Severity(str, Enum):
    """Alert severity level derived from rules + ML confidence."""
    LOW = "low"
    MEDIUM = "medium"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Investigation lifecycle status."""
    PENDING = "pending"
    INVESTIGATING = "investigating"
    COMPLETED = "completed"
    ERROR = "error"


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    USER = "user"
    HOSTNAME = "hostname"


class LogSourceType(str, Enum):
    """Source categories matching SOC log taxonomy."""
    FIREWALL = "firewall"
    AUTH = "auth"
    ENDPOINT = "endpoint"
    IDS = "ids"
    WEBSERVER = "webserver"
    DNS = "dns"


class Verdict(str, Enum):
    """Agent's final verdict on the alert."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    SUSPICIOUS = "suspicious"


class RecommendedAction(str, Enum):
    """Action recommendation for the SOC analyst."""
    CONTAIN = "contain"
    MONITOR = "monitor"
    IGNORE = "ignore"
    ESCALATE = "escalate"


# ──────────────────────────── IOCs ────────────────────────────


class IOC(BaseModel):
    """Single Indicator of Compromise extracted from an alert or log."""
    ioc_type: IOCType
    value: str
    context: str = Field(default="", description="Where this IOC was found")


class IOCCollection(BaseModel):
    """All IOCs extracted from an alert."""
    alert_id: str
    iocs: list[IOC] = Field(default_factory=list)
    extraction_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def ips(self) -> list[IOC]:
        return [i for i in self.iocs if i.ioc_type in (IOCType.IPV4, IOCType.IPV6)]

    @property
    def hashes(self) -> list[IOC]:
        return [i for i in self.iocs if i.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)]

    @property
    def domains(self) -> list[IOC]:
        return [i for i in self.iocs if i.ioc_type == IOCType.DOMAIN]

    @property
    def users(self) -> list[IOC]:
        return [i for i in self.iocs if i.ioc_type == IOCType.USER]


# ──────────────────────────── Log Events ────────────────────────────


class LogEvent(BaseModel):
    """Normalized log entry from any source.

    Unifies firewall, auth, endpoint, and IDS logs into a common schema
    while preserving source-specific metadata.
    """
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source_type: LogSourceType
    src_ip: str = ""
    dest_ip: str = ""
    src_port: int | None = None
    dest_port: int | None = None
    user: str = ""
    host: str = ""
    action: str = ""
    raw_event: str = Field(default="", description="Original log line for auditability")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific fields (signature, process_name, http_method, etc.)",
    )
    scenario_id: str = ""


# ──────────────────────────── Alerts ────────────────────────────


class Alert(BaseModel):
    """Raw SIEM alert ingested by SentinelSOC.

    This is the starting point of every investigation. It contains
    the original alert data as received from a SIEM/IDS/EDR.
    """
    id: str = Field(description="Unique alert identifier (e.g., ALT-2024-001)")
    timestamp: datetime
    source: str = Field(description="Originating system (e.g., Suricata, Fortinet, Sysmon)")
    title: str
    description: str
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Original alert payload from the SIEM",
    )
    status: AlertStatus = AlertStatus.PENDING
    severity: Severity | None = None
    scenario_id: str = Field(default="", description="Reference scenario for testing/demo")


# ──────────────────────────── Investigation ────────────────────────────


class InvestigationStep(BaseModel):
    """Single step in the agent's investigation chain.

    Records what the agent did, why, and what it found — ensuring
    full transparency of reasoning.
    """
    step_number: int
    action: str = Field(description="What the agent did (e.g., 'Query firewall logs for IP 23.22.63.114')")
    reasoning: str = Field(description="Why the agent chose this action")
    tool_used: str = ""
    query: str = Field(default="", description="Exact query or parameters used")
    result_summary: str = Field(default="", description="What the agent found")
    events_found: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ThreatIntelResult(BaseModel):
    """Result of a threat intelligence lookup for a single IOC."""
    ioc_value: str
    ioc_type: IOCType
    reputation: str = Field(description="malicious / suspicious / clean / unknown")
    confidence: float = Field(ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    source: str = Field(default="local", description="local / abuseipdb / virustotal")
    raw_response: dict[str, Any] = Field(default_factory=dict)


class CorrelationFinding(BaseModel):
    """A correlated chain of events across multiple log sources."""
    description: str
    events: list[UUID] = Field(
        default_factory=list,
        description="IDs of LogEvents involved in this correlation",
    )
    pattern: str = Field(
        default="",
        description="Attack pattern name (e.g., 'brute_force_then_login')",
    )
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class SeverityScore(BaseModel):
    """Combined severity assessment from rules and ML."""
    rule_score: float = Field(ge=0.0, le=100.0, description="Score from explicit rules (0-100)")
    ml_confidence: float = Field(
        ge=0.0, le=1.0,
        description="ML model confidence that traffic is malicious (0-1)",
    )
    final_score: float = Field(ge=0.0, le=100.0)
    severity: Severity
    rules_triggered: list[str] = Field(default_factory=list)
    ml_features_importance: dict[str, float] = Field(default_factory=dict)
    explanation: str = ""


class InvestigationResult(BaseModel):
    """Complete investigation output produced by the agent."""
    alert_id: str
    iocs: IOCCollection
    steps: list[InvestigationStep] = Field(default_factory=list)
    log_events: list[LogEvent] = Field(default_factory=list)
    correlations: list[CorrelationFinding] = Field(default_factory=list)
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)
    severity_score: SeverityScore | None = None
    verdict: Verdict | None = None
    recommended_action: RecommendedAction | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


# ──────────────────────────── Report ─────────────────────────────


class InvestigationReport(BaseModel):
    """Final structured report for human consumption.

    Generated from InvestigationResult, formatted for readability.
    """
    alert_id: str
    title: str
    executive_summary: str
    alert_info: dict[str, str]
    iocs_extracted: list[dict[str, str]]
    timeline: list[dict[str, str]]
    correlation_narrative: str
    threat_intel_results: list[dict[str, str]]
    severity_assessment: dict[str, Any]
    verdict: str
    recommended_action: str
    action_items: list[str]
    agent_reasoning: list[dict[str, str]]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    markdown: str = Field(default="", description="Full report rendered as Markdown")
