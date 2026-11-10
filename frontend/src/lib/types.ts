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
  password_changed_at?: string;
  created_at?: string;
}

export interface TestConnectionResult {
  status: string;
  is_connected: boolean;
  service_name: string;
  category: string;
  latency_ms: number;
  health: string;
  message: string;
  tested_at?: string;
}

export interface IocArtifact {
  artifact_id: number;
  alert_id: number;
  artifact_type: 'IP' | 'Hash' | 'URL' | 'Domain';
  value: string;
  threat_score: number;
  created_at: string;
}

export interface ContainmentAction {
  action_id: number;
  alert_id: number;
  action_type: string;
  status: string;
  executed_by?: string;
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
  title: string;
  cvss_score: number;
  severity: string;
  attack_vector: string;
  cwe?: string;
  description: string;
  hitl_remediation: string[];
  hotl_action: string;
  hotl_action_description: string;
  patches?: string[];
}

export interface VulnerabilityIntel {
  cves_detected: string[];
  max_cvss_score: number;
  vulnerabilities: VulnerabilityDetail[];
  hitl_remediation_steps: string[];
  hotl_autonomous_policy: {
    eligible_for_hotl: boolean;
    action_type: string;
    justification: string;
  };
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

export interface AlertDetail extends Alert {
  ioc_artifacts: IocArtifact[];
  playbook_executions: PlaybookExecution[];
  containment_actions: ContainmentAction[];
  incident_report?: IncidentReport | null;
  mitre_attack?: {
    id: string[];
    tactic: string[];
    technique: string[];
  };
  ai_summary?: string;
  vulnerability_intel?: VulnerabilityIntel;
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

export interface ConfigEntry {
  value: string;
  is_secret: boolean;
  updated_at?: string;
}

export type SystemConfigGroup = Record<string, Record<string, ConfigEntry>>;

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
