import {
  AdminReportData,
  AgentProposal,
  AgentStatus,
  Alert,
  AlertDetail,
  AnalystOption,
  ChangePasswordRequest,
  ChangePasswordResponse,
  ConfigUpdateItem,
  ConfigUpdateResult,
  CreatedUser,
  DashboardMetrics,
  HotlStatus,
  IngestTokenCreated,
  IngestTokenInfo,
  JsonObject,
  LoginResponse,
  MfaSetupResponse,
  MfaStatusResponse,
  Playbook,
  ProposalApprovalResult,
  ProposalList,
  RuntimeStatus,
  ServiceAccountKey,
  ServiceAccountPolicyChange,
  StepUpConfirmation,
  SystemConfigGroup,
  SystemLog,
  TestConnectionResult,
  User,
  VulnerabilityIntel,
} from './types';
import { ActionCatalog } from './actions';
import type { PlaybookImportReport, PlaybookImportRequest, PlaybookImportResult } from './playbookImport';
import {
  ApiError,
  NETWORK_ERROR_MESSAGE,
  isMfaEnrollmentRequired,
  isPasswordChangeRequired,
  parseErrorBody,
  parseRetryAfter,
} from './errors';
import {
  getStoredToken,
  setStoredToken,
  clearStoredToken,
  clearAuth,
  setStoredAuth,
  getStoredUser,
  setStoredUser,
  subscribeToAuth,
  TOKEN_KEY,
  USER_KEY,
  AUTH_CHANGE_EVENT,
} from './auth';

export {
  ApiError,
  getStoredToken,
  setStoredToken,
  clearStoredToken,
  clearAuth,
  setStoredAuth,
  getStoredUser,
  setStoredUser,
  subscribeToAuth,
  TOKEN_KEY,
  USER_KEY,
  AUTH_CHANGE_EVENT,
};

const API_BASE = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api`
  : '/api';

export const LOGIN_PATH = '/login';

function redirectToLogin(reason?: 'expired' | 'password' | 'mfa'): void {
  if (typeof window === 'undefined') return;
  if (window.location.pathname !== LOGIN_PATH) {
    window.location.assign(reason ? `${LOGIN_PATH}?reason=${reason}` : LOGIN_PATH);
  }
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(extra || {}) };
  const token = getStoredToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

/**
 * Turn an error response into an ApiError. A 401 (outside the sign-in form itself) ends the session and sends the
 * user to /login; a 403 that says a password change or MFA enrolment is still owed also goes to /login, where
 * the matching form opens.
 */
async function raiseForResponse(res: Response, isSignIn: boolean): Promise<never> {
  const body = await res.text().catch(() => '');
  const parsed = parseErrorBody(res.status, body);
  if (!isSignIn) {
    if (res.status === 401) {
      const hadSession = Boolean(getStoredToken());
      clearAuth();
      redirectToLogin(hadSession ? 'expired' : undefined);
    } else if (isPasswordChangeRequired(res.status, parsed.message)) {
      const cached = getStoredUser();
      if (cached) setStoredUser({ ...cached, must_change_password: true });
      redirectToLogin('password');
    } else if (isMfaEnrollmentRequired(res.status, parsed.message)) {
      const cached = getStoredUser();
      if (cached) setStoredUser({ ...cached, mfa_enrollment_required: true });
      redirectToLogin('mfa');
    }
  }
  throw new ApiError(res.status, parsed.message, {
    blockers: parsed.blockers,
    retryAfterSeconds: parseRetryAfter(res.headers.get('Retry-After')),
    code: parsed.code,
  });
}

async function send(url: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch {
    // fetch rejects only when the request never completed (offline, refused, blocked by CSP/CORS).
    throw new ApiError(0, NETWORK_ERROR_MESSAGE);
  }
}

export async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const extra = (options?.headers as Record<string, string> | undefined) || {};
  const headers = authHeaders({ 'Content-Type': 'application/json', ...extra });

  const res = await send(url, { ...options, headers });
  if (!res.ok) {
    // Failed sign-in attempts return 401 too; those must surface as form errors, not redirects.
    await raiseForResponse(res, url.endsWith('/auth/login'));
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(res.status, 'The API returned a response that is not valid JSON.');
  }
}

function jsonBody(data: unknown): string {
  return JSON.stringify(data);
}

/** Fetch a protected file (e.g. a PDF report) with the session token and save it. */
export async function downloadAuthenticated(url: string, fallbackFilename: string): Promise<void> {
  const res = await send(url, { headers: authHeaders() });
  if (!res.ok) {
    await raiseForResponse(res, false);
  }
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
  const filename = match ? decodeURIComponent(match[1]) : fallbackFilename;

  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000);
}

/**
 * Re-read the signed-in profile. Returns null (and clears the session) when the backend no longer accepts the
 * token. On a network failure the cached profile is returned so a flaky link does not sign everyone out; the
 * next API call re-checks the session and pages show their own error state.
 */
export async function syncCurrentUser(): Promise<User | null> {
  const token = getStoredToken();
  if (!token) {
    clearAuth();
    return null;
  }
  try {
    const user = await api.getCurrentUser();
    if (user && user.username) {
      setStoredAuth(user, token);
      return user;
    }
  } catch (err) {
    // 401: session invalid or expired. 403 from /auth/me: account disabled or not a human operator.
    if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
      clearAuth();
      return null;
    }
  }
  return getStoredUser();
}

export interface AdminReportParams {
  analyst?: string;
  period?: string;
  start_date?: string;
  end_date?: string;
  /** period "relative": last_n units (seconds | minutes | hours | days) back from now. */
  last_n?: number;
  last_unit?: string;
  /** Empty / omitted = all severities. */
  severity?: string[];
}

function adminReportQuery(params?: AdminReportParams): string {
  const query = new URLSearchParams();
  if (params?.analyst) query.append('analyst', params.analyst);
  if (params?.period) query.append('period', params.period);
  if (params?.start_date) query.append('start_date', params.start_date);
  if (params?.end_date) query.append('end_date', params.end_date);
  if (params?.last_n !== undefined) query.append('last_n', String(params.last_n));
  if (params?.last_unit) query.append('last_unit', params.last_unit);
  (params?.severity ?? []).forEach((s) => query.append('severity', s));
  return query.toString();
}

export interface ProposalQuery {
  status?: string;
  alert_id?: number;
  limit?: number;
  offset?: number;
}

export interface LogQuery {
  source?: string;
  seconds?: number;
  level?: string;
  search?: string;
  limit?: number;
}

export const api = {
  // --- Authentication & MFA -------------------------------------------------
  login: (username: string, password: string, mfa_code?: string): Promise<LoginResponse> =>
    fetchJson(`${API_BASE}/auth/login`, {
      method: 'POST',
      body: jsonBody({ username, password, mfa_code }),
    }),

  /**
   * Changes the password of the signed-in account (Bearer session). Proof of the old credential is the
   * current password (plus an MFA code when MFA is on), except for the forced first-login session.
   * Returns a fresh session; earlier tokens are invalidated.
   */
  changePassword: (data: ChangePasswordRequest): Promise<ChangePasswordResponse> =>
    fetchJson(`${API_BASE}/auth/change-password`, { method: 'POST', body: jsonBody(data) }),

  setupMfa: (): Promise<MfaSetupResponse> => fetchJson(`${API_BASE}/auth/mfa/setup`, { method: 'POST' }),

  verifyMfa: (code: string): Promise<MfaStatusResponse> =>
    fetchJson(`${API_BASE}/auth/mfa/verify`, { method: 'POST', body: jsonBody({ code }) }),

  /** While MFA is on the backend needs BOTH the account password and a current TOTP code. */
  disableMfa: (data: { password: string; code: string }): Promise<MfaStatusResponse> =>
    fetchJson(`${API_BASE}/auth/mfa/disable`, { method: 'POST', body: jsonBody(data) }),

  getCurrentUser: (): Promise<User> => fetchJson(`${API_BASE}/auth/me`),

  /** Revoke the session server-side (best effort), then clear local credentials. */
  logout: async (): Promise<void> => {
    const token = getStoredToken();
    try {
      if (token) {
        await fetch(`${API_BASE}/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
      }
    } catch {
      // Network failure: the local session is still cleared below; the token expires on its own.
    } finally {
      clearAuth();
    }
  },

  /** Unauthenticated liveness probe; true only for a 2xx answer. */
  getHealth: async (): Promise<boolean> => {
    try {
      const res = await fetch(`${API_BASE}/health`, { cache: 'no-store' });
      return res.ok;
    } catch {
      return false;
    }
  },

  // --- User accounts & RBAC (admin only) --------------------------------------
  getUsers: (): Promise<User[]> => fetchJson(`${API_BASE}/users`),

  createUser: (data: { username: string; role: string; confirmation?: StepUpConfirmation }): Promise<CreatedUser> =>
    fetchJson(`${API_BASE}/users`, { method: 'POST', body: jsonBody(data) }),

  /** The API key is returned once; agents send it as X-Phantom-Agent-Key. */
  createServiceAccount: (data: {
    username: string;
    expires_in_days?: number;
    ip_allowlist?: string[];
  }): Promise<ServiceAccountKey> =>
    fetchJson(`${API_BASE}/users/service-accounts`, { method: 'POST', body: jsonBody(data) }),

  /** Issues a new key; the previous one stops working immediately. The body optionally resets expiry / allow-list. */
  rotateServiceAccountKey: (userId: number, change?: ServiceAccountPolicyChange): Promise<ServiceAccountKey> =>
    fetchJson(`${API_BASE}/users/${userId}/rotate-api-key`, {
      method: 'POST',
      ...(change ? { body: jsonBody(change) } : {}),
    }),

  /** Change a service account's key expiry and allow-list without rotating the key. */
  updateServiceAccountPolicy: (userId: number, change: ServiceAccountPolicyChange): Promise<User> =>
    fetchJson(`${API_BASE}/users/${userId}/service-policy`, { method: 'PUT', body: jsonBody(change) }),

  updateUser: (
    userId: number,
    data: { role?: string; is_active?: boolean; compromised_reset_required?: boolean; confirmation?: StepUpConfirmation }
  ): Promise<User> => fetchJson(`${API_BASE}/users/${userId}`, { method: 'PUT', body: jsonBody(data) }),

  /** `confirmation` is required by the server when the target is another administrator. */
  resetUserPassword: (
    userId: number,
    confirmation?: StepUpConfirmation
  ): Promise<{ status: string; message: string; temporary_password?: string }> =>
    fetchJson(`${API_BASE}/users/${userId}/reset-password`, {
      method: 'POST',
      ...(confirmation ? { body: jsonBody({ confirmation }) } : {}),
    }),

  unlockUser: (userId: number): Promise<{ status: string; message: string }> =>
    fetchJson(`${API_BASE}/users/${userId}/unlock`, { method: 'POST' }),

  flagUserCompromised: (userId: number, confirmation?: StepUpConfirmation): Promise<{ status: string; message: string }> =>
    fetchJson(`${API_BASE}/users/${userId}/flag-compromised`, {
      method: 'POST',
      ...(confirmation ? { body: jsonBody({ confirmation }) } : {}),
    }),

  /** POST /users/{id}/delete, not DELETE: some proxies drop a request body on DELETE, and the confirmation is in it. */
  deleteUser: (userId: number, confirmation?: StepUpConfirmation): Promise<{ status: string; message: string }> =>
    fetchJson(`${API_BASE}/users/${userId}/delete`, {
      method: 'POST',
      ...(confirmation ? { body: jsonBody({ confirmation }) } : {}),
    }),

  // --- Webhook ingest tokens (admin only) -------------------------------------
  getIngestTokens: (): Promise<IngestTokenInfo[]> => fetchJson(`${API_BASE}/ingest-tokens`),

  /** The plaintext token is returned once, in `token`. */
  createIngestToken: (data: { name: string; expires_in_days?: number }): Promise<IngestTokenCreated> =>
    fetchJson(`${API_BASE}/ingest-tokens`, { method: 'POST', body: jsonBody(data) }),

  revokeIngestToken: (tokenId: number): Promise<IngestTokenInfo> =>
    fetchJson(`${API_BASE}/ingest-tokens/${tokenId}/revoke`, { method: 'POST' }),

  // --- Admin reporting ----------------------------------------------------------
  getAvailableAnalysts: (): Promise<AnalystOption[]> => fetchJson(`${API_BASE}/reports/analysts`),

  getAdminReport: (params?: AdminReportParams): Promise<AdminReportData> =>
    fetchJson(`${API_BASE}/reports/analyst-activity?${adminReportQuery(params)}`),

  downloadAdminReportPdf: (params?: AdminReportParams): Promise<void> =>
    downloadAuthenticated(
      `${API_BASE}/reports/analyst-activity/pdf?${adminReportQuery(params)}`,
      `phantom_soar_analyst_report_${params?.period || 'month'}.pdf`
    ),

  // --- Configuration & integrations ---------------------------------------------
  getConfigurations: (): Promise<SystemConfigGroup> => fetchJson(`${API_BASE}/configuration`),

  /** An empty key_value for a secret keeps the stored value unless clear=true. 409 carries {message, blockers}. */
  updateConfigurations: (configs: ConfigUpdateItem[]): Promise<ConfigUpdateResult> =>
    fetchJson(`${API_BASE}/configuration`, { method: 'POST', body: jsonBody({ configs }) }),

  getRuntimeStatus: (): Promise<RuntimeStatus> => fetchJson(`${API_BASE}/configuration/runtime-status`),

  /**
   * Admin only. service_name is one of the integration ids (virustotal, wazuh, okta, ...).
   * Stored settings are tested unless overrides are given (to test values before saving them).
   */
  testConnection: (
    category: string,
    service_name: string,
    overrides?: { api_key?: string; endpoint_url?: string; username?: string }
  ): Promise<TestConnectionResult> =>
    fetchJson<TestConnectionResult>(`${API_BASE}/configuration/test-connection`, {
      method: 'POST',
      body: jsonBody({ category, service_name, ...(overrides || {}) }),
    }),

  getHotlStatus: (): Promise<HotlStatus> => fetchJson(`${API_BASE}/configuration/hotl-status`),

  /** Admin only. Enabling can answer 409 {message, blockers} until protected assets are listed. */
  toggleHotl: (enabled?: boolean): Promise<HotlStatus> =>
    fetchJson(`${API_BASE}/configuration/hotl-toggle`, {
      method: 'POST',
      body: jsonBody(enabled !== undefined ? { enabled } : {}),
    }),

  // --- Metrics ---------------------------------------------------------------------
  getDashboardMetrics: (): Promise<DashboardMetrics> => fetchJson(`${API_BASE}/alerts/metrics/dashboard`),

  // --- Alerts & forensics ------------------------------------------------------------
  getAlerts: (params?: { severity?: string; status?: string; skip?: number; limit?: number }): Promise<Alert[]> => {
    const query = new URLSearchParams();
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.skip) query.append('skip', String(params.skip));
    if (params?.limit) query.append('limit', String(params.limit));
    return fetchJson(`${API_BASE}/alerts?${query.toString()}`);
  },

  /**
   * Admin only. Two steps: the backend issues a one-time confirmation token (valid about two minutes, bound to
   * this session) and the purge must present it as X-Confirm-Token. Call this only after the operator confirmed.
   */
  purgeAlerts: async (): Promise<{ status: string; message: string; deleted_alerts?: number }> => {
    const issued = await fetchJson<{ confirm_token: string }>(`${API_BASE}/alerts/purge/confirm`);
    return fetchJson(`${API_BASE}/alerts/purge`, {
      method: 'DELETE',
      headers: { 'X-Confirm-Token': issued.confirm_token },
    });
  },

  getAlertDetail: (alertId: number): Promise<AlertDetail> => fetchJson(`${API_BASE}/alerts/${alertId}`),

  approveAlert: (alertId: number): Promise<JsonObject> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/approve`, { method: 'POST' }),

  dismissAlert: (alertId: number): Promise<JsonObject> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/dismiss`, { method: 'POST' }),

  submitAlertDecision: (
    alertId: number,
    decision: 'take_action' | 'keep_and_monitor' | 'dismiss',
    notes?: string
  ): Promise<JsonObject> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/decision`, {
      method: 'POST',
      body: jsonBody({ decision, notes }),
    }),

  /** Re-run TIP enrichment for the alert's IOCs in the background. */
  triggerBackgroundTipEnrichment: (alertId: number): Promise<JsonObject> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/enrich-background`, { method: 'POST' }),

  getAlertVulnerabilities: (alertId: number): Promise<VulnerabilityIntel> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/vulnerabilities`),

  executeNvdHotl: (alertId: number): Promise<JsonObject> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/vulnerabilities/execute-hotl`, { method: 'POST' }),

  downloadAlertReport: (alertId: number): Promise<void> =>
    downloadAuthenticated(`${API_BASE}/alerts/${alertId}/report`, `phantom_soar_incident_${alertId}.pdf`),

  // --- AI agent (AI_API_CONTRACT.md) ----------------------------------------------------
  getAgentStatus: (): Promise<AgentStatus> => fetchJson(`${API_BASE}/agent/status`),

  getProposals: (params?: ProposalQuery): Promise<ProposalList> => {
    const query = new URLSearchParams();
    if (params?.status) query.append('status', params.status);
    if (params?.alert_id !== undefined) query.append('alert_id', String(params.alert_id));
    query.append('limit', String(params?.limit ?? 50));
    query.append('offset', String(params?.offset ?? 0));
    return fetchJson(`${API_BASE}/agent/proposals?${query.toString()}`);
  },

  getProposal: (proposalId: number): Promise<AgentProposal> =>
    fetchJson(`${API_BASE}/agent/proposals/${proposalId}`),

  /** Responder role. 409: AI disabled, key missing, rate limited or alert busy. 502: the model call failed. */
  triageAlert: (alertId: number): Promise<AgentProposal> =>
    fetchJson(`${API_BASE}/agent/triage/${alertId}`, { method: 'POST', body: jsonBody({}) }),

  /** action_indexes omitted = approve every action. 409 when the proposal was already decided. */
  approveProposal: (
    proposalId: number,
    data: { notes?: string; action_indexes?: number[] }
  ): Promise<ProposalApprovalResult> =>
    fetchJson(`${API_BASE}/agent/proposals/${proposalId}/approve`, { method: 'POST', body: jsonBody(data) }),

  rejectProposal: (proposalId: number, data: { notes?: string }): Promise<AgentProposal> =>
    fetchJson(`${API_BASE}/agent/proposals/${proposalId}/reject`, { method: 'POST', body: jsonBody(data) }),

  // --- Playbooks ---------------------------------------------------------------------------
  getPlaybooks: (activeOnly: boolean = false): Promise<Playbook[]> =>
    fetchJson(`${API_BASE}/playbooks?active_only=${activeOnly}`),

  getPlaybookTemplates: (): Promise<Array<Pick<Playbook, 'name' | 'target_threat' | 'execution_mode' | 'workflow_logic' | 'is_active'>>> =>
    fetchJson(`${API_BASE}/playbooks/templates`),

  /** Actions a playbook step may use plus the runner's pseudo-steps. */
  getPlaybookActions: (): Promise<ActionCatalog> => fetchJson(`${API_BASE}/playbooks/actions`),

  createPlaybook: (data: Partial<Playbook>): Promise<Playbook> =>
    fetchJson(`${API_BASE}/playbooks`, { method: 'POST', body: jsonBody(data) }),

  updatePlaybook: (playbookId: number, data: Partial<Playbook>): Promise<Playbook> =>
    fetchJson(`${API_BASE}/playbooks/${playbookId}`, { method: 'PUT', body: jsonBody(data) }),

  deletePlaybook: (playbookId: number): Promise<JsonObject> =>
    fetchJson(`${API_BASE}/playbooks/${playbookId}`, { method: 'DELETE' }),

  togglePlaybook: (playbookId: number): Promise<{ is_active: boolean }> =>
    fetchJson(`${API_BASE}/playbooks/${playbookId}/toggle`, { method: 'PATCH' }),

  /** Admin only: validate a playbook pack and report what an import would do. Writes nothing. */
  previewPlaybookImport: (request: PlaybookImportRequest): Promise<PlaybookImportReport> =>
    fetchJson(`${API_BASE}/playbooks/import/preview`, { method: 'POST', body: jsonBody(request) }),

  /** Admin only: import a previewed pack (needs expected_sha256). Playbooks are created inactive and in HITL mode. */
  importPlaybooks: (request: PlaybookImportRequest): Promise<PlaybookImportResult> =>
    fetchJson(`${API_BASE}/playbooks/import`, { method: 'POST', body: jsonBody(request) }),

  /** Admin only, simulation mode only (409 otherwise): sends lab payloads through the real ingest pipeline. */
  seedDemoData: (): Promise<{ status?: string; message?: string }> =>
    fetchJson(`${API_BASE}/demo/seed`, { method: 'POST' }),

  // --- Telemetry & security logs (append-only: there is no write or delete API) -------------
  getLogs: (params?: LogQuery): Promise<SystemLog[]> => {
    const query = new URLSearchParams();
    if (params?.source) query.append('source', params.source);
    if (params?.seconds) query.append('seconds', String(params.seconds));
    if (params?.level) query.append('level', params.level);
    if (params?.search) query.append('search', params.search);
    if (params?.limit) query.append('limit', String(params.limit));
    return fetchJson(`${API_BASE}/logs?${query.toString()}`);
  },
};
