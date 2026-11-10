export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export type AlertStatus = 'New' | 'Triaged' | 'Contained' | 'Resolved' | 'Closed' | 'Monitoring';
export type ExecutionMode = 'HOTL' | 'HITL';

export interface User {
  user_id: number;
  username: string;
  role: string;
  must_change_password?: boolean;
  is_active?: boolean;
  mfa_enabled?: boolean;
  compromised_reset_required?: boolean;
  is_service_account?: boolean;
  api_key_prefix?: string | null;
  password_changed_at?: string;
  created_at?: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  mfa_required?: boolean;
  user: User;
}

export interface TestConnectionResult {
  /** "Connected" | "Not Configured" | "Auth failed" | "Unreachable" | "Error" | "Configured (not tested to avoid posting)" */
  status: string;
  is_connected: boolean;
  service?: string;
  service_name: string;
  category: string;
  latency_ms?: number | null;
  http_status?: number | null;
  health?: string;
  message: string;
  tested_at?: string;
}

// --- Threat intelligence ---------------------------------------------------

export type IocVerdict = 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
export type EnrichmentStatus = 'enriched' | 'partial' | 'unavailable' | 'not_configured' | 'pending';
export type ProviderStatus = 'live' | 'not_found' | 'not_configured' | 'error' | 'lab_fixture' | 'skipped';

export interface TipProviderResult {
  provider: string;
  status: ProviderStatus | string;
  threat_score: number | null;
  verdict: string | null;
  summary?: Record<string, unknown> | null;
  error?: string | null;
  queried_at?: string | null;
}

/** Full enrich_ioc() result as stored on IocArtifact.tip_results. */
export interface TipResults {
  artifact_type?: string;
  value?: string;
  threat_score?: number;
  verdict?: IocVerdict;
  severity?: Severity | null;
  enrichment_status?: EnrichmentStatus;
  providers?: Record<string, TipProviderResult>;
  consensus?: Record<string, unknown>;
  [legacyKey: string]: unknown;
}

export interface IocArtifact {
  artifact_id: number;
  alert_id: number;
  artifact_type: 'IP' | 'Hash' | 'URL' | 'Domain' | string;
  value: string;
  threat_score: number;
  verdict?: IocVerdict | string;
  enrichment_status?: EnrichmentStatus | string;
  tip_results?: TipResults | null;
  created_at: string;
}

// --- Response actions ------------------------------------------------------

export type ActionExecutionMode = 'live' | 'simulated' | 'skipped' | 'blocked' | 'failed';

export interface ContainmentAction {
  action_id: number;
  alert_id: number;
  action_type: string;
  status: string;
  executed_by?: string;
  target?: string | null;
  connector?: string | null;
  execution_mode?: ActionExecutionMode | string | null;
  details?: unknown;
  timestamp: string;
}

export interface PlaybookExecution {
  execution_id: number;
  alert_id: number;
  playbook_id?: number | null;
  playbook_name?: string | null;
  status: string;
  mttr_seconds: number;
  executed_at: string;
}

export interface IncidentReport {
  report_id: number;
  alert_id: number;
  pdf_path: string;
  generated_at: string;
}

export interface VulnerabilityDetail {
  cve_id: string;
  title?: string;
  cvss_score?: number | null;
  severity?: string | null;
  attack_vector?: string | null;
  cwe?: string | null;
  description?: string | null;
  hitl_remediation?: string[];
  hotl_action?: string;
  hotl_action_description?: string;
  patches?: string[];
  status?: string;
  queried_at?: string;
}

export interface VulnerabilityIntel {
  cves_detected: string[];
  max_cvss_score?: number | null;
  vulnerabilities: VulnerabilityDetail[];
  hitl_remediation_steps?: string[];
  hotl_autonomous_policy?: {
    eligible_for_hotl: boolean;
    action_type?: string;
    justification?: string;
    action_description?: string;
  };
  status?: string;
  message?: string;
}

export interface Alert {
  alert_id: number;
  rule_id: string;
  source: string;
  severity: Severity;
  status: AlertStatus;
  analyst_decision?: string;
  assigned_analyst?: string;
  resolved_by?: string;
  resolved_at?: string;
  raw_payload?: any;
  created_at: string;
  ioc_count?: number;
  max_threat_score?: number;
}

export interface MitreAttack {
  id: string[];
  tactic: string[];
  technique: string[];
}

export interface AlertDetail extends Alert {
  ioc_artifacts: IocArtifact[];
  playbook_executions: PlaybookExecution[];
  containment_actions: ContainmentAction[];
  incident_report?: IncidentReport | null;
  mitre_attack?: MitreAttack;
  triage_summary?: string;
  simulation_mode?: boolean;
  playbook?: Playbook | null;
  vulnerability_intel?: VulnerabilityIntel;
}

export interface PlaybookStep {
  order?: number;
  step?: number;
  action: string;
  connector?: string;
  params?: Record<string, unknown>;
  [extra: string]: unknown;
}

export interface Playbook {
  playbook_id: number;
  name: string;
  target_threat: string;
  execution_mode: ExecutionMode;
  workflow_logic: any;
  is_active: boolean;
  created_at: string;
}

export interface DashboardMetrics {
  total_alerts: number;
  new_alerts: number;
  triaged_alerts: number;
  contained_alerts: number;
  resolved_alerts: number;
  unresolved_alerts?: number;
  review_gates_count?: number;
  automated_actions: number;
  avg_mttr_seconds: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

// --- Configuration ---------------------------------------------------------

export interface ConfigEntry {
  value: string;
  is_secret: boolean;
  is_set: boolean;
  preview: string | null;
  updated_at: string | null;
}

/** GET /api/configuration: {CATEGORY: {key_name: ConfigEntry}} */
export type SystemConfigGroup = Record<string, Record<string, ConfigEntry>>;

export interface ConfigUpdateItem {
  category: string;
  key_name: string;
  key_value: string;
  is_secret: boolean;
  clear?: boolean;
}

export interface RuntimeStatus {
  simulation_mode: boolean;
  hotl_enabled: boolean;
  integrations: {
    virustotal: boolean;
    abuseipdb: boolean;
    otx: boolean;
    threatfox: boolean;
    nvd: boolean;
    wazuh: boolean;
    okta: boolean;
    jira: boolean;
    slack: boolean;
    [name: string]: boolean;
  };
  agent_autonomy?: 'recommend_only' | 'low_impact' | 'policy' | string;
  agent_min_confidence?: number;
}

export interface HotlStatus {
  hotl_enabled: boolean;
  mode: string;
  status: string;
  message?: string;
}

export interface SystemLog {
  log_id: number;
  source: string;
  level: string;
  message: string;
  target?: string;
  details?: any;
  created_at: string;
}

export interface AnalystMetrics {
  analyst_username: string;
  role: string;
  cases_assigned: number;
  cases_resolved: number;
  escalated_count: number;
  monitored_count: number;
  dismissed_count: number;
  containment_actions_taken: number;
  avg_mttr_seconds: number;
}

export interface AdminReportData {
  period: string;
  start_date: string;
  end_date: string;
  filtered_analyst?: string | null;
  total_cases_reviewed: number;
  total_containment_actions: number;
  average_mttr_seconds: number;
  analyst_breakdown: AnalystMetrics[];
  cases: any[];
  action_logs: any[];
}
