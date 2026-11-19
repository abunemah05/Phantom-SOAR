// Shapes of the Phantom SOAR API (backend/routers/*, backend/schemas.py, AI_API_CONTRACT.md).
// Response parsing in the UI stays defensive: optional fields may be missing on older backends.

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
/**
 * Processing = ingest/playbook run in flight.
 * Simulated  = response actions were only rehearsed (simulation mode): NOT contained.
 */
export type AlertStatus =
  | 'New'
  | 'Processing'
  | 'Triaged'
  | 'Contained'
  | 'Simulated'
  | 'Resolved'
  | 'Closed'
  | 'Monitoring';
export type ExecutionMode = 'HOTL' | 'HITL';

export type JsonObject = Record<string, unknown>;

// --- Users & authentication -------------------------------------------------

export interface User {
  user_id: number;
  username: string;
  role: string;
  must_change_password?: boolean;
  is_active?: boolean;
  mfa_enabled?: boolean;
  /** Policy require_mfa_for_admin is on and this administrator has not enrolled MFA yet. */
  mfa_enrollment_required?: boolean;
  compromised_reset_required?: boolean;
  is_service_account?: boolean;
  /** The account created at first start; cannot be deleted or disabled. */
  is_bootstrap_admin?: boolean;
  api_key_prefix?: string | null;
  /** Service accounts: API key expiry, source allow-list and last use. */
  expires_at?: string | null;
  ip_allowlist?: string[] | null;
  last_used_at?: string | null;
  last_used_ip?: string | null;
  password_changed_at?: string | null;
  created_at?: string | null;
  /** GET /users only: what the signed-in administrator may do to this account (backend/rbac.py is the authority). */
  account_actions?: Partial<Record<AccountActionKey, AccountActionState>>;
}

export type AccountActionKey =
  | 'change_role'
  | 'set_active'
  | 'reset_password'
  | 'set_compromised'
  | 'unlock'
  | 'delete'
  | 'rotate_key'
  | 'service_policy';

export interface AccountActionState {
  allowed: boolean;
  /** Why the action is refused (when !allowed) or why it needs a confirmation (when step_up). */
  reason?: string | null;
  /** The acting administrator must re-enter their own password (and an MFA code when they use MFA). */
  step_up?: boolean;
  code?: string;
}

/** Sent with a sensitive account change: the acting administrator's OWN credentials. */
export interface StepUpConfirmation {
  current_password: string;
  mfa_code?: string;
}

export interface LoginResponse {
  /** Empty string while mfa_required is true. */
  access_token: string;
  token_type: string;
  mfa_required?: boolean;
  mfa_enrollment_required?: boolean;
  user: User;
}

export interface ChangePasswordRequest {
  /** Accepted only for older clients; must equal the signed-in user. */
  username?: string;
  /** Optional only for a forced first-login or compromised-reset change. */
  current_password?: string;
  new_password: string;
  /** Required with current_password when MFA is enabled. */
  mfa_code?: string;
}

export interface ChangePasswordResponse {
  status?: string;
  message?: string;
  access_token?: string;
  token_type?: string;
  user?: User;
}

export interface MfaSetupResponse {
  secret: string;
  provisioning_uri: string;
  issuer: string;
  account: string;
  message: string;
}

export interface MfaStatusResponse {
  mfa_enabled: boolean;
  status: string;
  message: string;
}

export interface CreatedUser extends User {
  /** Shown once; the operator must change it at first sign-in. */
  temporary_password?: string;
}

export interface ServiceAccountKey extends User {
  /** Shown once; only a digest is stored. */
  api_key: string;
}

export interface ServiceAccountPolicyChange {
  expires_in_days?: number;
  clear_expiry?: boolean;
  /** [] removes the restriction; omitted leaves it unchanged. */
  ip_allowlist?: string[];
}

export interface IngestTokenInfo {
  id: number;
  name: string;
  token_prefix: string;
  created_by?: string | null;
  created_at?: string | null;
  last_used_at?: string | null;
  expires_at?: string | null;
  revoked_at?: string | null;
  status: 'active' | 'revoked' | 'expired' | string;
}

export interface IngestTokenCreated extends IngestTokenInfo {
  /** Shown once. */
  token: string;
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
export type ProviderStatus =
  | 'live'
  | 'not_found'
  | 'not_configured'
  | 'error'
  | 'rate_limited'
  | 'lab_fixture'
  | 'skipped';

export interface TipProviderResult {
  provider: string;
  status: ProviderStatus | string;
  threat_score: number | null;
  verdict: string | null;
  summary?: JsonObject | null;
  error?: string | null;
  /** Set when status is rate_limited. */
  retry_after_seconds?: number | null;
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
  simulated?: boolean;
  incomplete?: boolean;
  retry_after_seconds?: number | null;
  providers?: Record<string, TipProviderResult>;
  consensus?: JsonObject;
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

/** Per-CVE and overall NVD lookup states (backend/integrations/nvd.py). */
export type NvdCveStatus = 'live' | 'not_found' | 'not_configured' | 'unavailable' | 'rate_limited' | 'pending';
export type NvdLookupStatus = 'pending' | 'partial' | 'live' | 'no_cves' | 'unavailable' | 'rate_limited' | 'not_configured';

export interface VulnerabilityDetail {
  cve_id: string;
  title?: string;
  cvss_score?: number | null;
  cvss_version?: string | null;
  severity?: string | null;
  attack_vector?: string | null;
  cwe?: string | null;
  description?: string | null;
  known_exploited?: boolean | null;
  hitl_remediation?: string[];
  hotl_action?: string;
  hotl_action_description?: string;
  patches?: string[];
  nvd_url?: string;
  status?: NvdCveStatus | string;
  error?: string | null;
  retry_after_seconds?: number | null;
  queried_at?: string;
}

export interface VulnerabilityIntel {
  cves_detected: string[];
  cves_truncated?: number;
  max_cvss_score?: number | null;
  vulnerabilities: VulnerabilityDetail[];
  hitl_remediation_steps?: string[];
  hotl_autonomous_policy?: {
    eligible_for_hotl: boolean;
    action_type?: string;
    justification?: string;
    action_description?: string;
  };
  lookup_status?: NvdLookupStatus | string;
  incomplete?: boolean;
  pending_cves?: string[];
  retry_after_seconds?: number | null;
  /** Older/unavailable shape: {status: "unavailable", error}. */
  status?: string;
  error?: string;
  message?: string;
}

export interface RawPayload {
  rule?: { description?: string; level?: number | string; id?: string | number; [k: string]: unknown };
  agent?: { name?: string; ip?: string; id?: string; [k: string]: unknown };
  full_log?: string;
  [k: string]: unknown;
}

export interface Alert {
  alert_id: number;
  rule_id: string;
  source: string;
  severity: Severity;
  status: AlertStatus;
  analyst_decision?: string | null;
  assigned_analyst?: string | null;
  resolved_by?: string | null;
  resolved_at?: string | null;
  raw_payload?: RawPayload | null;
  created_at: string;
  ioc_count?: number;
  max_threat_score?: number;
  malicious_ioc_count?: number;
}

export interface MitreAttack {
  id: string[];
  tactic: string[];
  technique: string[];
  /** "telemetry" | "playbook" when present */
  source?: string;
}

export interface AlertEntities {
  hosts: string[];
  ips: string[];
  users: string[];
  hashes: string[];
  files: string[];
  processes: string[];
  domains: string[];
  urls: string[];
}

export interface AlertRouting {
  mode: ExecutionMode | string;
  reasons: string[];
  evidence: string[];
}

// --- AI agent (AI_API_CONTRACT.md) -------------------------------------------

export type AgentVerdict = 'malicious' | 'suspicious' | 'benign' | 'unknown';
export type ProposalStatus =
  | 'pending_approval'
  | 'auto_executed'
  | 'partially_executed'
  | 'approved'
  | 'rejected'
  | 'blocked'
  | 'no_action';
export type AgentAutonomy = 'recommend_only' | 'low_impact' | 'policy';

export interface ProposedAction {
  action: string;
  target?: string | null;
  params?: JsonObject;
}

/** policy_evaluation[i] lines up with proposed_actions[i]. */
export interface PolicyEvaluation {
  action?: string;
  target?: string | null;
  allowed?: boolean;
  requires_approval?: boolean;
  reasons?: string[];
  [extra: string]: unknown;
}

/** execution_results[i]: a ContainmentAction.to_dict() or {skipped: reason}. */
export interface ExecutionResult {
  action_id?: number;
  action_type?: string;
  status?: string;
  execution_mode?: ActionExecutionMode | string | null;
  target?: string | null;
  executed_by?: string;
  details?: unknown;
  skipped?: string;
  [extra: string]: unknown;
}

export interface AgentProposal {
  proposal_id: number;
  alert_id: number;
  agent_name: string;
  verdict: AgentVerdict | string;
  confidence: number;
  summary?: string | null;
  reasoning?: string | null;
  proposed_actions: ProposedAction[];
  policy_evaluation: PolicyEvaluation[];
  execution_results: ExecutionResult[];
  status: ProposalStatus | string;
  decided_by?: string | null;
  decided_at?: string | null;
  decision_notes?: string | null;
  created_at: string;
}

export interface AgentStatus {
  enabled: boolean;
  configured: boolean;
  auto_triage?: boolean;
  model?: string | null;
  autonomy: AgentAutonomy | string;
  min_confidence?: number;
  simulation_mode?: boolean;
  hotl_enabled?: boolean;
  send_raw_payload?: boolean;
  max_alerts_per_minute?: number;
  pending_proposals: number;
  /** "database" | "environment" | null. Never the key itself. */
  key_source?: 'database' | 'environment' | null;
}

export interface ProposalList {
  items: AgentProposal[];
  total: number;
  limit: number;
  offset: number;
}

export interface ProposalApprovalResult {
  proposal: AgentProposal;
  results?: ExecutionResult[];
}

export interface AlertDetail extends Alert {
  ioc_artifacts: IocArtifact[];
  playbook_executions: PlaybookExecution[];
  containment_actions: ContainmentAction[];
  incident_report?: IncidentReport | null;
  mitre_attack?: MitreAttack;
  triage_summary?: string;
  simulation_mode?: boolean;
  hotl_enabled?: boolean;
  playbook?: Playbook | null;
  routing?: AlertRouting | null;
  entities?: AlertEntities | null;
  agent_proposals?: AgentProposal[];
  vulnerability_intel?: VulnerabilityIntel;
}

export interface PlaybookStep {
  order?: number;
  step?: number;
  action: string;
  connector?: string;
  params?: JsonObject;
  [extra: string]: unknown;
}

export interface WorkflowLogic {
  mitre_id?: string;
  picerl_phase?: string;
  keywords?: string[];
  steps?: PlaybookStep[];
  [extra: string]: unknown;
}

export interface Playbook {
  playbook_id: number;
  name: string;
  target_threat: string;
  execution_mode: ExecutionMode;
  /** Object, or a JSON string on legacy rows. */
  workflow_logic: WorkflowLogic | string;
  is_active: boolean;
  created_at: string;
}

export interface DashboardMetrics {
  total_alerts: number;
  new_alerts: number;
  triaged_alerts: number;
  contained_alerts: number;
  /** Rehearsed only (simulation mode): not contained, not resolved. */
  simulated_alerts?: number;
  resolved_alerts: number;
  unresolved_alerts?: number;
  review_gates_count?: number;
  /** Actions that ran live or simulated; live_actions / simulated_actions split them. */
  automated_actions: number;
  live_actions?: number;
  simulated_actions?: number;
  blocked_actions?: number;
  failed_actions?: number;
  skipped_actions?: number;
  /** null when no playbook run has completed yet. */
  avg_mttr_seconds: number | null;
  mttr_sample_size?: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

// --- Configuration ---------------------------------------------------------

export type ConfigSource = 'database' | 'environment' | 'default' | null;

export interface ConfigEntry {
  /** Effective value; always "" for secrets. */
  value: string;
  is_secret: boolean;
  is_set: boolean;
  /** Constant mask for a set secret, else null. Never contains characters of the secret. */
  preview: string | null;
  /** Where the effective value comes from. */
  source?: ConfigSource;
  env_var?: string;
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

export interface ConfigUpdateResult {
  status?: string;
  message?: string;
  updated?: string[];
  unchanged?: string[];
}

export interface RuntimeStatus {
  simulation_mode: boolean;
  hotl_enabled: boolean;
  /** ai = an OpenRouter key exists (not that AI triage is enabled; see ai_enabled). */
  integrations: Record<string, boolean>;
  ai_enabled?: boolean;
  agent_autonomy?: AgentAutonomy | string;
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
  target?: string | null;
  details?: JsonObject | null;
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

export interface ReportCase {
  alert_id: number;
  rule_id: string;
  severity: string;
  status: string;
  resolved_by?: string | null;
  analyst_decision?: string | null;
  created_at: string;
}

export interface AdminReportData {
  period: string;
  start_date: string;
  end_date: string;
  /** start_date / end_date are ISO-8601 in this zone (always "UTC") and both inclusive. */
  timezone?: string;
  /** preset | absolute | relative */
  range_mode?: string;
  generated_at?: string | null;
  filtered_analyst?: string | null;
  /** Empty = all severities. */
  filtered_severities?: string[];
  /** Cases in the report per severity, most severe first (zeros included). */
  severity_breakdown?: Record<string, number>;
  total_cases_reviewed: number;
  total_containment_actions: number;
  /** live / simulated / skipped / blocked / failed */
  containment_by_mode?: Record<string, number>;
  average_mttr_seconds: number;
  mttr_sample_size?: number;
  analyst_breakdown: AnalystMetrics[];
  cases: ReportCase[];
  action_logs: JsonObject[];
}

export interface AnalystOption {
  user_id: number;
  username: string;
  role: string;
  is_active: boolean;
}
