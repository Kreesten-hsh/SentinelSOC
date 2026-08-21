export type Severity = 'critical' | 'medium' | 'low';
export type Verdict = 'true_positive' | 'false_positive' | 'suspicious';
export type RecommendedAction = 'contain' | 'escalate' | 'monitor' | 'ignore';
export type AlertStatus = 'pending' | 'investigating' | 'completed' | 'error';

export interface AlertSummary {
  id: string;
  timestamp: string;
  source: string;
  title: string;
  description: string;
  status: AlertStatus;
  severity: Severity | null;
  scenario_id: string;
  verdict: Verdict | null;
  recommended_action: RecommendedAction | null;
  severity_score: number | null;
}

export interface IOC {
  ioc_type: string;
  value: string;
  context: string;
}

export interface InvestigationStep {
  step_number: number;
  action: string;
  reasoning: string;
  tool_used: string;
  query: string;
  result_summary: string;
  events_found: number;
  timestamp: string;
}

export interface CorrelationFinding {
  description: string;
  events: string[];
  pattern: string;
  confidence: number;
}

export interface ThreatIntelResult {
  ioc_value: string;
  ioc_type: string;
  reputation: string;
  confidence: number;
  tags: string[];
  source: string;
  raw_response?: Record<string, any>;
}

export interface SeverityScore {
  rule_score: number;
  ml_confidence: number;
  final_score: number;
  severity: Severity;
  rules_triggered: string[];
  ml_features_importance: Record<string, number>;
  explanation: string;
}

export interface LogEvent {
  id: string;
  timestamp: string;
  source_type: string;
  src_ip: string;
  dest_ip: string;
  src_port?: number;
  dest_port?: number;
  user: string;
  host: string;
  action: string;
  raw_event: string;
  metadata: Record<string, any>;
  scenario_id?: string;
}

export interface InvestigationResult {
  alert_id: string;
  iocs: {
    alert_id: string;
    iocs: IOC[];
    extraction_timestamp: string;
  };
  steps: InvestigationStep[];
  log_events: LogEvent[];
  correlations: CorrelationFinding[];
  threat_intel: ThreatIntelResult[];
  severity_score: SeverityScore | null;
  verdict: Verdict | null;
  recommended_action: RecommendedAction | null;
  started_at: string;
  completed_at: string | null;
}

export interface AlertDetail extends AlertSummary {
  raw_data: Record<string, any>;
  investigation: InvestigationResult | null;
  has_report: boolean;
}

export interface StatsResponse {
  total_alerts: number;
  pending_alerts: number;
  completed_alerts: number;
  critical_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  true_positives: number;
  false_positives: number;
  suspicious: number;
}

export interface ReportData {
  alert_id: string;
  title: string;
  executive_summary: string;
  markdown: string;
  data: Record<string, any>;
  generated_at: string;
}
