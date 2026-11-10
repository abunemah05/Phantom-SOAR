import { 
  Alert, 
  AlertDetail, 
  DashboardMetrics, 
  Playbook, 
  User, 
  SystemConfigGroup, 
  TestConnectionResult, 
  SystemLog,
  AdminReportData,
  VulnerabilityIntel
} from './types';
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

export async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string> || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (!res.ok) {
    if (res.status === 401) {
      // Clear poisoned/stale token and cached credentials
      clearAuth();
    }
    let errorMsg = `API Error [${res.status}]`;
    try {
      const errorText = await res.text();
      try {
        const errJson = JSON.parse(errorText);
        errorMsg = errJson.detail || errJson.message || errorText || errorMsg;
      } catch {
        if (errorText) errorMsg = errorText;
      }
    } catch {
      // Fallback if reading body stream completely fails
    }
    throw new Error(errorMsg);
  }

  return res.json();
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
  } catch (err: any) {
    if (err.message && (err.message.includes("401") || err.message.includes("Unauthorized"))) {
      clearAuth();
      return null;
    }
  }
  return getStoredUser();
}

export const api = {
  // Authentication & MFA (NIST SP 800-63B Compliant)
  login: (username: string, password: string, mfa_code?: string): Promise<{ access_token: string; token_type: string; mfa_required?: boolean; user: User }> =>
    fetchJson(`${API_BASE}/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ username, password, mfa_code }),
    }),

  changePassword: (data: { username: string; current_password: string; new_password: string }): Promise<{ status: string; message: string }> =>
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

  disableMfa: (): Promise<{ mfa_enabled: boolean; status: string; message: string }> =>
    fetchJson(`${API_BASE}/auth/mfa/disable`, { method: 'POST' }),

  getCurrentUser: (): Promise<User> =>
    fetchJson(`${API_BASE}/auth/me`),

  logout: () => {
    clearAuth();
    return fetchJson(`${API_BASE}/auth/logout`, { method: 'POST' });
  },

  // User Accounts & RBAC Management (Admin Only)
  getUsers: (): Promise<User[]> =>
    fetchJson(`${API_BASE}/users`),

  createUser: (data: { username: string; role: string; mfa_enabled?: boolean }): Promise<User> =>
    fetchJson(`${API_BASE}/users`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updateUser: (userId: number, data: { role?: string; is_active?: boolean; compromised_reset_required?: boolean }): Promise<User> =>
    fetchJson(`${API_BASE}/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  resetUserPassword: (userId: number): Promise<{ status: string; message: string; default_password: string }> =>
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

  // Admin Reporting Dashboard (Exclusively for Admins)
  getAvailableAnalysts: (): Promise<Array<{ user_id: number; username: string; role: string; is_active: boolean }>> =>
    fetchJson(`${API_BASE}/reports/analysts`),

  getAdminReport: (params?: { analyst?: string; period?: string; start_date?: string; end_date?: string }): Promise<AdminReportData> => {
    const query = new URLSearchParams();
    if (params?.analyst) query.append('analyst', params.analyst);
    if (params?.period) query.append('period', params.period);
    if (params?.start_date) query.append('start_date', params.start_date);
    if (params?.end_date) query.append('end_date', params.end_date);
    return fetchJson(`${API_BASE}/reports/analyst-activity?${query.toString()}`);
  },

  getAdminReportPdfUrl: (params?: { analyst?: string; period?: string; start_date?: string; end_date?: string }): string => {
    const query = new URLSearchParams();
    if (params?.analyst) query.append('analyst', params.analyst);
    if (params?.period) query.append('period', params.period);
    if (params?.start_date) query.append('start_date', params.start_date);
    if (params?.end_date) query.append('end_date', params.end_date);
    return `${API_BASE}/reports/analyst-activity/pdf?${query.toString()}`;
  },

  // Configuration & Integrations (AI / EDR / XDR / SIEM / TIP / Firewall / ITSM)
  getConfigurations: (): Promise<SystemConfigGroup> =>
    fetchJson(`${API_BASE}/configuration`),

  updateConfigurations: (configs: Array<{ category: string; key_name: string; key_value: string; is_secret: boolean }>) =>
    fetchJson(`${API_BASE}/configuration`, {
      method: 'POST',
      body: JSON.stringify({ configs }),
    }),

  testConnection: (category: string, service_name: string, api_key?: string, endpoint_url?: string): Promise<TestConnectionResult> =>
    fetchJson<TestConnectionResult>(`${API_BASE}/configuration/test-connection`, {
      method: 'POST',
      body: JSON.stringify({ category, service_name, api_key, endpoint_url }),
    }),

  // HOTL Autonomous Containment Engine Toggle & Status
  getHotlStatus: (): Promise<{ hotl_enabled: boolean; mode: string; status: string }> =>
    fetchJson(`${API_BASE}/configuration/hotl-status`),

  toggleHotl: (enabled?: boolean): Promise<{ hotl_enabled: boolean; mode: string; status: string; message: string }> =>
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

  // Action decision specifically for Low tickets: Take Action vs Keep for Monitoring
  submitAlertDecision: (alertId: number, decision: 'take_action' | 'keep_and_monitor' | 'dismiss', notes?: string) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/decision`, {
      method: 'POST',
      body: JSON.stringify({ decision, notes }),
    }),

  // Multi-TIP Parallel Background Enrichment
  triggerBackgroundTipEnrichment: (alertId: number) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/enrich-background`, { method: 'POST' }),

  // NVD Vulnerability Context & HOTL Automated Actions
  getAlertVulnerabilities: (alertId: number): Promise<VulnerabilityIntel> =>
    fetchJson(`${API_BASE}/alerts/${alertId}/vulnerabilities`),

  executeCveHotlAction: (alertId: number) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/vulnerabilities/execute-hotl`, { method: 'POST' }),

  executeNvdHotl: (alertId: number) =>
    fetchJson(`${API_BASE}/alerts/${alertId}/vulnerabilities/execute-hotl`, { method: 'POST' }),

  getReportDownloadUrl: (alertId: number) =>
    `${API_BASE}/alerts/${alertId}/report`,

  // Playbooks
  getPlaybooks: (activeOnly: boolean = false): Promise<Playbook[]> =>
    fetchJson(`${API_BASE}/playbooks?active_only=${activeOnly}`),

  getPlaybookTemplates: (): Promise<any[]> =>
    fetchJson(`${API_BASE}/playbooks/templates`),

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

  // Demo Seeder
  seedDemoData: () =>
    fetchJson(`${API_BASE}/demo/seed`, { method: 'POST' }),

  // Wazuh Webhook simulator
  ingestAlert: (payload: any) =>
    fetchJson(`${API_BASE}/webhooks/wazuh`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

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

  seedLogs: () =>
    fetchJson(`${API_BASE}/logs/seed`, { method: 'POST' }),

  clearLogs: () =>
    fetchJson(`${API_BASE}/logs`, { method: 'DELETE' }),
};
