import {
  Alert,
  AlertDetail,
  DashboardMetrics,
  Playbook,
  User,
  LoginResponse,
  SystemConfigGroup,
  ConfigUpdateItem,
  RuntimeStatus,
  HotlStatus,
  TestConnectionResult,
  SystemLog,
  AdminReportData,
  VulnerabilityIntel
} from './types';
import { ActionCatalog } from './actions';
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
  AUTH_CHANGE_EVENT
} from './auth';

export {
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
  AUTH_CHANGE_EVENT
};

const API_BASE = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api`
  : '/api';

export const LOGIN_PATH = '/login';
const PASSWORD_CHANGE_REQUIRED = 'password change required';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function redirectToLogin(): void {
  if (typeof window === 'undefined') return;
  if (window.location.pathname !== LOGIN_PATH) {
    window.location.assign(LOGIN_PATH);
  }
}

async function readErrorMessage(res: Response): Promise<string> {
  let errorMsg = `API Error [${res.status}]`;
  try {
    const errorText = await res.text();
    try {
      const errJson = JSON.parse(errorText);
      const detail = errJson.detail ?? errJson.message;
      if (typeof detail === 'string') {
        errorMsg = detail;
      } else if (Array.isArray(detail)) {
        // FastAPI validation errors: [{loc, msg, type}]
        errorMsg = detail.map((d: any) => d?.msg || JSON.stringify(d)).join('; ');
      } else if (errorText) {
        errorMsg = errorText;
      }
    } catch {
      if (errorText) errorMsg = errorText;
    }
  } catch {
    // body unreadable; keep the status-based message
  }
  return errorMsg;
}

function authHeaders(extra?: HeadersInit): Record<string, string> {
  const headers: Record<string, string> = { ...((extra as Record<string, string>) || {}) };
  const token = getStoredToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

/**
 * Handle an error response: a 401 clears the session and sends the user to /login,
 * as does a 403 telling us the account must change its password first.
 */
async function handleErrorResponse(res: Response, isAuthRequest: boolean): Promise<never> {
  const message = await readErrorMessage(res);
  if (!isAuthRequest) {
    if (res.status === 401) {
      clearAuth();
      redirectToLogin();
    } else if (res.status === 403 && message.toLowerCase().includes(PASSWORD_CHANGE_REQUIRED)) {
      // Flag the cached profile so /login opens the change-password form.
      const cached = getStoredUser();
      if (cached) setStoredUser({ ...cached, must_change_password: true });
      redirectToLogin();
    }
  }
  throw new ApiError(res.status, message);
}

export async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = authHeaders({
    'Content-Type': 'application/json',
    ...((options?.headers as Record<string, string>) || {}),
  });

  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    // Failed sign-in attempts return 401 too; those must surface as form errors, not redirects.
    const isAuthRequest = url.includes('/auth/login') || url.includes('/auth/change-password');
    await handleErrorResponse(res, isAuthRequest);
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

/** Fetch a protected file (e.g. a PDF report) with the session token and save it. */
export async function downloadAuthenticated(url: string, fallbackFilename: string): Promise<void> {
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) {
    await handleErrorResponse(res, false);
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
  // Network failure: keep the cached profile; the next API call re-checks the session.
  return getStoredUser();
}

function adminReportQuery(params?: { analyst?: string; period?: string; start_date?: string; end_date?: string }): string {
  const query = new URLSearchParams();
  if (params?.analyst) query.append('analyst', params.analyst);
  if (params?.period) query.append('period', params.period);
  if (params?.start_date) query.append('start_date', params.start_date);
  if (params?.end_date) query.append('end_date', params.end_date);
  return query.toString();
}

export const api = {
  // Authentication & MFA
  login: (username: string, password: string, mfa_code?: string): Promise<LoginResponse> =>
    fetchJson(`${API_BASE}/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ username, password, mfa_code }),
    }),

  /** Returns a fresh session (access_token + user) when the backend issues one. */
  changePassword: (data: { username: string; current_password: string; new_password: string; mfa_code?: string }): Promise<{
    status?: string;
    message?: string;
    access_token?: string;
    token_type?: string;
    user?: User;
  }> =>
    fetchJson(`${API_BASE}/auth/change-password`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  setupMfa: (): Promise<{ secret: string; provisioning_uri: string; issuer: string; account: string; message: string }> =>
    fetchJson(`${API_BASE}/auth/mfa/setup`, { method: 'POST' }),

  verifyMfa: (code: string): Promise<{ mfa_enabled: boolean; status: string; message: string }> =>
    fetchJson(`${API_BASE}/auth/mfa/verify`, {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  disableMfa: (code?: string): Promise<{ mfa_enabled: boolean; status: string; message: string }> =>
    fetchJson(`${API_BASE}/auth/mfa/disable`, {
      method: 'POST',
      body: JSON.stringify(code ? { code } : {}),
    }),

  getCurrentUser: (): Promise<User> =>
    fetchJson(`${API_BASE}/auth/me`),

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
      // Network failure: the local session is still cleared below.
    } finally {
      clearAuth();
    }
  },

  // User Accounts & RBAC Management (Admin Only)
  getUsers: (): Promise<User[]> =>
    fetchJson(`${API_BASE}/users`),

  createUser: (data: { username: string; role: string; mfa_enabled?: boolean }): Promise<User & { temporary_password?: string; default_password?: string }> =>
    fetchJson(`${API_BASE}/users`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  /** Admin only. The API key is returned once; agents send it as X-Phantom-Agent-Key. */
  createServiceAccount: (username: string): Promise<User & { api_key: string }> =>
    fetchJson(`${API_BASE}/users/service-accounts`, {
      method: 'POST',
      body: JSON.stringify({ username }),
    }),

  /** Admin only. Issues a new key; the previous one stops working immediately. */
  rotateServiceAccountKey: (userId: number): Promise<User & { api_key: string }> =>
    fetchJson(`${API_BASE}/users/${userId}/rotate-api-key`, { method: 'POST' }),

  updateUser: (userId: number, data: { role?: string; is_active?: boolean; compromised_reset_required?: boolean }): Promise<User> =>
    fetchJson(`${API_BASE}/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  resetUserPassword: (userId: number): Promise<{ status: string; message: string; temporary_password?: string; default_password?: string }> =>
    fetchJson(`${API_BASE}/users/${userId}/reset-password`, {
      method: 'POST',
    }),

  flagUserCompromised: (userId: number): Promise<{ status: string; message: string }> =>
    fetchJson(`${API_BASE}/users/${userId}/flag-compromised`, {
      method: 'POST',
    }),

  deleteUser: (userId: number): Promise<{ status: string; message: string }> =>
    fetchJson(`${API_BASE}/users/${userId}`, {
      method: 'DELETE',
    }),

  // Admin Reporting
  getAvailableAnalysts: (): Promise<Array<{ user_id: number; username: string; role: string; is_active: boolean }>> =>
    fetchJson(`${API_BASE}/reports/analysts`),

  getAdminReport: (params?: { analyst?: string; period?: string; start_date?: string; end_date?: string }): Promise<AdminReportData> =>
    fetchJson(`${API_BASE}/reports/analyst-activity?${adminReportQuery(params)}`),

  downloadAdminReportPdf: (params?: { analyst?: string; period?: string; start_date?: string; end_date?: string }): Promise<void> =>
    downloadAuthenticated(
      `${API_BASE}/reports/analyst-activity/pdf?${adminReportQuery(params)}`,
      `phantom_soar_analyst_report_${params?.period || 'month'}.pdf`
    ),

  // Configuration & Integrations
  getConfigurations: (): Promise<SystemConfigGroup> =>
    fetchJson(`${API_BASE}/configuration`),

  /** An empty key_value for a secret keeps the stored value unless clear=true. */
  updateConfigurations: (configs: ConfigUpdateItem[]): Promise<unknown> =>
    fetchJson(`${API_BASE}/configuration`, {
      method: 'POST',
      body: JSON.stringify({ configs }),
    }),

  getRuntimeStatus: (): Promise<RuntimeStatus> =>
    fetchJson(`${API_BASE}/configuration/runtime-status`),

  /**
   * Admin only. service_name is one of the RuntimeStatus.integrations keys (virustotal, wazuh, okta, ...).
   * Stored settings are tested unless overrides are given (to test values before saving them).
   */
  testConnection: (
    category: string,
    service_name: string,
    overrides?: { api_key?: string; endpoint_url?: string; username?: string }
  ): Promise<TestConnectionResult> =>
    fetchJson<TestConnectionResult>(`${API_BASE}/configuration/test-connection`, {
      method: 'POST',
      body: JSON.stringify({ category, service_name, ...(overrides || {}) }),
    }),

  getHotlStatus: (): Promise<HotlStatus> =>
    fetchJson(`${API_BASE}/configuration/hotl-status`),

  toggleHotl: (enabled?: boolean): Promise<HotlStatus> =>
    fetchJson(`${API_BASE}/configuration/hotl-toggle`, {
      method: 'POST',
      body: JSON.stringify(enabled !== undefined ? { enabled } : {}),
    }),

  // Metrics
  getDashboardMetrics: (): Promise<DashboardMetrics> =>
    fetchJson(`${API_BASE}/alerts/metrics/dashboard`),

  // Alerts & Forensics
  getAlerts: (params?: { severity?: string; status?: string; skip?: number; limit?: number }): Promise<Alert[]> => {
    const query = new URLSearchParams();
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.skip) query.append('skip', String(params.skip));
    if (params?.limit) query.append('limit', String(params.limit));
    return fetchJson(`${API_BASE}/alerts?${query.toString()}`);
  },

  purgeAlerts: (): Promise<{ status: string; message: string }> =>
    fetchJson(`${API_BASE}/alerts/purge`, { method: 'DELETE' }),

  getAlertDetail: (alertId: number): Promise<AlertDetail> =>
    fetchJson(`${API_BASE}/alerts/${alertId}`),

  approveAlert: (alertId: number) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/approve`, { method: 'POST' }),

  dismissAlert: (alertId: number) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/dismiss`, { method: 'POST' }),

  submitAlertDecision: (alertId: number, decision: 'take_action' | 'keep_and_monitor' | 'dismiss', notes?: string) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/decision`, {
      method: 'POST',
      body: JSON.stringify({ decision, notes }),
    }),

  /** Re-run TIP enrichment for the alert's IOCs in the background. */
  triggerBackgroundTipEnrichment: (alertId: number) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/enrich-background`, { method: 'POST' }),

  getAlertVulnerabilities: (alertId: number): Promise<VulnerabilityIntel> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/vulnerabilities`),

  executeNvdHotl: (alertId: number) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/vulnerabilities/execute-hotl`, { method: 'POST' }),

  downloadAlertReport: (alertId: number): Promise<void> =>
    downloadAuthenticated(`${API_BASE}/alerts/${alertId}/report`, `phantom_soar_incident_${alertId}.pdf`),

  // Playbooks
  getPlaybooks: (activeOnly: boolean = false): Promise<Playbook[]> =>
    fetchJson(`${API_BASE}/playbooks?active_only=${activeOnly}`),

  getPlaybookTemplates: (): Promise<Array<Pick<Playbook, 'name' | 'target_threat' | 'execution_mode' | 'workflow_logic' | 'is_active'>>> =>
    fetchJson(`${API_BASE}/playbooks/templates`),

  /** Actions a playbook step may use plus the runner's pseudo-steps. */
  getPlaybookActions: (): Promise<ActionCatalog> =>
    fetchJson(`${API_BASE}/playbooks/actions`),

  createPlaybook: (data: Partial<Playbook>): Promise<Playbook> =>
    fetchJson(`${API_BASE}/playbooks`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updatePlaybook: (playbookId: number, data: Partial<Playbook>): Promise<Playbook> =>
    fetchJson(`${API_BASE}/playbooks/${playbookId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  deletePlaybook: (playbookId: number) =>
    fetchJson(`${API_BASE}/playbooks/${playbookId}`, { method: 'DELETE' }),

  togglePlaybook: (playbookId: number): Promise<{ is_active: boolean }> =>
    fetchJson(`${API_BASE}/playbooks/${playbookId}/toggle`, { method: 'PATCH' }),

  /** Admin only, simulation mode only (409 otherwise): sends lab payloads through the real ingest pipeline. */
  seedDemoData: (): Promise<{ status?: string; message?: string; [key: string]: unknown }> =>
    fetchJson(`${API_BASE}/demo/seed`, { method: 'POST' }),

  // Telemetry & Security Logs
  getLogs: (params?: { source?: string; seconds?: number; level?: string; search?: string; limit?: number }): Promise<SystemLog[]> => {
    const query = new URLSearchParams();
    if (params?.source) query.append('source', params.source);
    if (params?.seconds) query.append('seconds', String(params.seconds));
    if (params?.level) query.append('level', params.level);
    if (params?.search) query.append('search', params.search);
    if (params?.limit) query.append('limit', String(params.limit));
    return fetchJson(`${API_BASE}/logs?${query.toString()}`);
  },

  /** Admin only. */
  clearLogs: () =>
    fetchJson(`${API_BASE}/logs`, { method: 'DELETE' }),
};
