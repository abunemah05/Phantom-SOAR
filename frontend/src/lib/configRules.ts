// Client-side mirror of the validation rules in backend/routers/config.py (_validate_value) plus presentation
// metadata for known settings. The page renders whatever GET /api/configuration returns: keys without metadata
// still get a sensible control (inferred from the secret flag and the current value). The backend stays the
// authority; this only gives instant feedback before a save is attempted.

import { ConfigEntry } from "./types";

export type FieldKind = "secret" | "text" | "url" | "bool" | "list" | "number" | "select";

export interface SelectOption {
  value: string;
  label: string;
  help?: string;
}

export interface FieldMeta {
  label?: string;
  kind?: FieldKind;
  help?: string;
  placeholder?: string;
  options?: SelectOption[];
}

export interface NumericRule {
  min: number;
  max: number;
  integer: boolean;
}

// Same ranges as backend NUMERIC_KEYS.
export const NUMERIC_RULES: Record<string, NumericRule> = {
  vt_requests_per_minute: { min: 0, max: 100000, integer: true },
  vt_requests_per_day: { min: 0, max: 10_000_000, integer: true },
  abuseipdb_daily_limit: { min: 0, max: 10_000_000, integer: true },
  nvd_requests_per_30s: { min: 1, max: 100000, integer: true },
  tip_max_wait_seconds: { min: 0, max: 600, integer: false },
  vt_malicious_weight: { min: 0, max: 10, integer: false },
  vt_suspicious_weight: { min: 0, max: 10, integer: false },
  vt_malicious_threshold: { min: 0.001, max: 1, integer: false },
  vt_min_detections: { min: 0, max: 1000, integer: false },
  tip_malicious_threshold: { min: 1, max: 100, integer: true },
  tip_suspicious_threshold: { min: 1, max: 100, integer: true },
  tip_critical_threshold: { min: 1, max: 100, integer: true },
  wazuh_default_block_hours: { min: 0, max: 720, integer: true },
  wazuh_default_rate_limit_hours: { min: 0, max: 720, integer: true },
  agent_min_confidence: { min: 0, max: 1, integer: false },
  // AI category (AI_API_CONTRACT.md): the contract gives no range, so only a sane whole-number bound is enforced here.
  ai_max_alerts_per_minute: { min: 1, max: 600, integer: true },
};

export const BOOL_KEYS = new Set([
  "hotl_enabled",
  "simulation_mode",
  "siem_verify_tls",
  "require_mfa_for_admin",
  "simulation_confirmed_in_production",
  "ai_enabled",
  "ai_auto_triage",
  "ai_send_raw_payload",
]);

export const URL_KEYS = new Set(["siem_manager_url", "jira_base_url", "jira_webhook_url", "slack_webhook_url"]);
export const LIST_KEYS = new Set([
  "protected_hosts",
  "protected_users",
  "protected_ips",
  "wazuh_windows_agent_ids",
  "wazuh_firewall_agent_ids",
]);
export const AGENT_AUTONOMY_LEVELS = ["recommend_only", "low_impact", "policy"] as const;
export const JIRA_API_VERSIONS = ["2", "3"] as const;

const TRUE_WORDS = new Set(["1", "true", "yes", "on"]);
const FALSE_WORDS = new Set(["0", "false", "no", "off"]);
const HOSTNAME_RE = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^[0-9A-Fa-f:.]+$/;

export function isIpOrCidr(item: string): boolean {
  const [addr, prefix, extra] = item.split("/");
  if (extra !== undefined || !addr) return false;
  const isV4 = IPV4_RE.test(addr);
  const isV6 = !isV4 && addr.includes(":") && IPV6_RE.test(addr) && (addr.match(/::/g) || []).length <= 1;
  if (!isV4 && !isV6) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (isV4 ? 32 : 128);
}

export function hostOnly(value: string): string {
  const v = value.trim();
  try {
    return new URL(v.includes("://") ? v : `https://${v}`).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export function splitList(value: string): string[] {
  return value
    .replace(/\n/g, ",")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

/** Normalised boolean text the backend stores, or null when the text is not a boolean word. */
export function normalizeBool(value: string): "true" | "false" | null {
  const lowered = value.trim().toLowerCase();
  if (TRUE_WORDS.has(lowered)) return "true";
  if (FALSE_WORDS.has(lowered)) return "false";
  return null;
}

/**
 * Validate one non-secret setting. Returns an error message, or null when the value is acceptable
 * (an empty value is always acceptable: it means "use the default / environment").
 */
export function validateConfigValue(key: string, rawValue: string): string | null {
  const value = rawValue.trim();
  if (value.length > 1000) return "Value exceeds 1000 characters.";
  if (value === "") return null;

  if (BOOL_KEYS.has(key)) {
    return normalizeBool(value) ? null : "Expected true or false.";
  }
  const rule = NUMERIC_RULES[key];
  if (rule) {
    const number = Number(value);
    const range = `${rule.min} and ${rule.max}`;
    if (!Number.isFinite(number)) return `Expected a number between ${range}.`;
    if (number < rule.min || number > rule.max || (rule.integer && !Number.isInteger(number))) {
      return `Expected a ${rule.integer ? "whole number" : "number"} between ${range}.`;
    }
    return null;
  }
  if (key === "jira_api_version") {
    return (JIRA_API_VERSIONS as readonly string[]).includes(value) ? null : "Expected 2 or 3.";
  }
  if (key === "agent_autonomy") {
    return (AGENT_AUTONOMY_LEVELS as readonly string[]).includes(value)
      ? null
      : `Expected one of ${AGENT_AUTONOMY_LEVELS.join(", ")}.`;
  }
  if (URL_KEYS.has(key)) {
    try {
      const url = new URL(value);
      return (url.protocol === "http:" || url.protocol === "https:") && url.hostname ? null : "Expected an http(s) URL.";
    } catch {
      return "Expected an http(s) URL.";
    }
  }
  if (key === "okta_domain") {
    const host = hostOnly(value);
    return host && HOSTNAME_RE.test(host) ? null : "Expected a hostname such as your-org.okta.com.";
  }
  if (key === "protected_ips") {
    const bad = splitList(value).find((item) => !isIpOrCidr(item));
    return bad ? `'${bad}' is not an IP address or CIDR range.` : null;
  }
  if (key === "openrouter_model") {
    return /\s/.test(value) ? "A model slug cannot contain spaces (expected vendor/model)." : null;
  }
  return null;
}

export function inferFieldKind(key: string, entry: ConfigEntry | undefined): FieldKind {
  if (entry?.is_secret) return "secret";
  if (BOOL_KEYS.has(key)) return "bool";
  if (key === "agent_autonomy") return "select";
  if (NUMERIC_RULES[key]) return "number";
  if (URL_KEYS.has(key) || key.endsWith("_url")) return "url";
  if (LIST_KEYS.has(key) || key.endsWith("_ids")) return "list";
  const v = (entry?.value || "").trim().toLowerCase();
  if (v === "true" || v === "false") return "bool";
  return "text";
}

const WORDS: Record<string, string> = {
  api: "API",
  url: "URL",
  ip: "IP",
  ips: "IPs",
  ai: "AI",
  vt: "VirusTotal",
  nvd: "NVD",
  tip: "TIP",
  siem: "SIEM",
  tls: "TLS",
  ca: "CA",
  ar: "AR",
  mfa: "MFA",
  hotl: "HOTL",
  ids: "IDs",
  otx: "OTX",
  okta: "Okta",
  jira: "Jira",
  slack: "Slack",
  wazuh: "Wazuh",
  openrouter: "OpenRouter",
  abuseipdb: "AbuseIPDB",
  virustotal: "VirusTotal",
  threatfox: "ThreatFox",
};

/** "wazuh_ar_block_command" -> "Wazuh AR block command". Fallback label for keys without metadata. */
export function labelFromKey(key: string): string {
  const words = key.split("_").filter(Boolean).map((w) => WORDS[w] || w);
  if (words.length === 0) return key;
  const first = words[0];
  words[0] = first.charAt(0).toUpperCase() + first.slice(1);
  return words.join(" ");
}

const AUTONOMY_OPTIONS: SelectOption[] = [
  { value: "recommend_only", label: "Recommend only", help: "Every agent proposal waits for an analyst decision." },
  { value: "low_impact", label: "Low impact", help: "Low-impact actions run automatically when confidence meets the minimum; everything else waits for approval." },
  { value: "policy", label: "Policy", help: "Low- and medium-impact actions run automatically when confidence meets the minimum. High-impact actions always need approval." },
];

/** Known settings: nicer labels and help. Anything not listed is still rendered generically. */
export const FIELD_META: Record<string, FieldMeta> = {
  virustotal_api_key: { label: "VirusTotal API key" },
  abuseipdb_api_key: { label: "AbuseIPDB API key" },
  otx_api_key: { label: "AlienVault OTX API key" },
  threatfox_api_key: { label: "ThreatFox Auth-Key" },
  nvd_api_key: { label: "NIST NVD API key", help: "Optional: NVD works without a key at a much lower rate limit." },
  vt_requests_per_minute: { label: "VirusTotal requests per minute", help: "Local budget. The free tier allows 4 per minute; 0 or empty uses the built-in default." },
  vt_requests_per_day: { label: "VirusTotal requests per day", help: "Local budget. The free tier allows 500 per day." },
  abuseipdb_daily_limit: { label: "AbuseIPDB requests per day" },
  nvd_requests_per_30s: { label: "NVD requests per 30 seconds", help: "NVD allows 5 without a key and 50 with one." },
  tip_max_wait_seconds: { label: "Max wait for a rate-limit slot (seconds)", help: "Longer waits answer \"rate limited\" instead of blocking the alert." },
  vt_malicious_weight: { label: "VirusTotal weight: malicious engines" },
  vt_suspicious_weight: { label: "VirusTotal weight: suspicious engines" },
  vt_malicious_threshold: { label: "VirusTotal malicious ratio", help: "Fraction of engines (0.001 to 1) at which the score reaches the Malicious threshold." },
  vt_min_detections: { label: "VirusTotal minimum detections", help: "Fewer weighted detections can never score Malicious." },
  tip_malicious_threshold: { label: "Malicious score threshold (1-100)" },
  tip_suspicious_threshold: { label: "Suspicious score threshold (1-100)" },
  tip_critical_threshold: { label: "Critical severity score threshold (1-100)" },
  siem_manager_url: { label: "Wazuh Manager API URL", placeholder: "https://wazuh-manager.example.org:55000" },
  siem_user: { label: "API username" },
  siem_password: { label: "API password" },
  siem_verify_tls: { label: "Verify TLS certificate", help: "Turn off only for lab managers with self-signed certificates; prefer a CA bundle below." },
  wazuh_ca_bundle: { label: "Wazuh CA bundle path", help: "PEM file the backend trusts for the manager certificate (instead of disabling verification)." },
  wazuh_ar_script_prefix: { label: "Active-response script prefix", help: "See wazuh/README.md for the commands the manager must define." },
  wazuh_windows_agent_ids: { label: "Windows agent IDs", help: "Comma or line separated Wazuh agent ids that run the Windows scripts." },
  wazuh_firewall_agent_ids: { label: "Firewall agent IDs", help: "Agents that receive firewall (block IP) commands." },
  wazuh_default_block_hours: { label: "Default IP block duration (hours)", help: "0 uses the active-response script's own default." },
  wazuh_default_rate_limit_hours: { label: "Default rate-limit duration (hours)" },
  wazuh_ar_block_command: { label: "AR command: block IP" },
  wazuh_ar_unblock_command: { label: "AR command: unblock IP" },
  wazuh_ar_isolate_command: { label: "AR command: isolate host" },
  wazuh_ar_unisolate_command: { label: "AR command: un-isolate host" },
  wazuh_ar_kill_command: { label: "AR command: kill process" },
  wazuh_ar_quarantine_command: { label: "AR command: quarantine file" },
  wazuh_ar_rate_limit_command: { label: "AR command: rate limit" },
  okta_domain: { label: "Okta domain", placeholder: "your-org.okta.com" },
  okta_login_domain: { label: "Okta login domain", help: "Only if users sign in on a different (custom) domain." },
  okta_api_token: { label: "Okta API token" },
  jira_base_url: { label: "Jira base URL", placeholder: "https://your-org.atlassian.net" },
  jira_email: { label: "Jira account email" },
  jira_api_token: { label: "Jira API token" },
  jira_project_key: { label: "Jira project key", placeholder: "SEC" },
  jira_webhook_url: { label: "Jira automation webhook URL", help: "Alternative to the REST API." },
  jira_api_version: { label: "Jira REST API version", help: "2 or 3." },
  jira_issue_type: { label: "Jira issue type", placeholder: "Task" },
  slack_webhook_url: { label: "Slack incoming webhook URL" },
  simulation_mode: {
    label: "Simulation mode",
    help: "On (default): a hard stop. No response action is sent to Wazuh, Okta, Jira or Slack, even where credentials are saved; actions are recorded as SIMULATED, and lab threat-intel fixtures answer for documentation IPs. Threat-intel lookups are unaffected. Off: every connector with credentials acts on real systems and the others record SKIPPED. Turn off only after reviewing the protected lists, and only while you are testing.",
  },
  hotl_enabled: {
    label: "HOTL autonomous containment",
    help: "On: HOTL playbooks may contain automatically when there is real evidence and policy allows it. Off: every action waits for analyst approval. Needs protected hosts/IPs and protected users to be listed first; until they are, it is ignored even if switched on.",
  },
  simulation_confirmed_in_production: { label: "Confirm simulation mode in production", help: "Explicit acknowledgement that simulation mode is intended although real connectors are configured." },
  require_mfa_for_admin: { label: "Require MFA for administrators", help: "Administrators without MFA must enrol an authenticator before using the console." },
  protected_hosts: { label: "Protected hosts", placeholder: "dc01\nprod-db-01", help: "One per line (or comma separated). Automated actors are denied; analysts are warned." },
  protected_users: { label: "Protected users", placeholder: "breakglass-admin\nsvc-backup" },
  protected_ips: { label: "Protected IPs / CIDR ranges", placeholder: "10.0.0.1\n192.168.10.0/24" },
  agent_autonomy: { label: "Agent autonomy", kind: "select", options: AUTONOMY_OPTIONS },
  agent_min_confidence: { label: "Minimum confidence for automatic execution (0 - 1)", help: "Model-stated confidence is not calibrated: keep autonomy on recommend only until you have measured accuracy." },
  openrouter_api_key: { label: "OpenRouter API key", help: "Write-only. Never sent back to the browser and never shown to the model." },
  openrouter_model: { label: "OpenRouter model", placeholder: "vendor/model", help: "Model slug from openrouter.ai/models." },
  ai_enabled: { label: "Enable built-in AI triage", help: "Master switch. Off: no alert data is ever sent to a model." },
  ai_auto_triage: { label: "Triage new alerts automatically", help: "Needs AI triage enabled. Off: analysts start triage with the \"Run AI triage\" button." },
  ai_max_alerts_per_minute: { label: "AI alerts per minute", help: "Hard local rate limit (cost control)." },
  ai_send_raw_payload: { label: "Send raw alert payload to the model", help: "Off (recommended): only a redacted summary leaves your network. On: the full payload, which may contain usernames, hostnames and credentials, is sent to a third party." },
};

export interface CategoryMeta {
  title: string;
  description: string;
}

export const CATEGORY_ORDER = ["TIP", "SIEM", "IAM", "ITSM", "ORCHESTRATION", "AGENT", "AI"];

export const CATEGORY_META: Record<string, CategoryMeta> = {
  TIP: {
    title: "Threat Intelligence",
    description: "IOC reputation lookups and rate-limit / scoring tuning. Providers without a key report \"not configured\"; no score is ever invented for them.",
  },
  SIEM: {
    title: "SIEM & Active Response (Wazuh)",
    description: "Wazuh manager API used for read-only checks and active response. Alerts themselves arrive through the authenticated webhooks.",
  },
  IAM: { title: "Identity Provider (Okta)", description: "Used by disable_account, revoke_user_sessions and force_password_reset." },
  ITSM: { title: "Ticketing & Notifications", description: "Jira tickets (REST API or an automation webhook) and Slack notifications." },
  ORCHESTRATION: { title: "Orchestration & Safety Guards", description: "Global switches and assets that automated actors (playbooks, AI) must never act on." },
  AGENT: { title: "AI Agent Policy", description: "Limits the policy engine applies to every action an AI agent or the built-in AI proposes." },
  AI: {
    title: "Built-in AI Triage (OpenRouter)",
    description: "Optional model-assisted triage. The key is write-only; with the default autonomy every proposal still waits for an analyst.",
  },
};

export function categoryMeta(category: string): CategoryMeta {
  return CATEGORY_META[category] || { title: labelFromKey(category.toLowerCase()), description: "Settings reported by the backend." };
}

export function sortedCategories(categories: string[]): string[] {
  const known = CATEGORY_ORDER.filter((c) => categories.includes(c));
  const extra = categories.filter((c) => !CATEGORY_ORDER.includes(c)).sort();
  return [...known, ...extra];
}

export function fieldLabel(key: string): string {
  return FIELD_META[key]?.label || labelFromKey(key);
}

/** Settings used by connection tests: which form fields feed which test override. */
export interface ServiceTestDef {
  id: string;
  label: string;
  /** Key in runtime-status integrations when it differs from the service id (openrouter -> ai). */
  integrationKey?: string;
  overrides: { api_key?: string; endpoint_url?: string; username?: string };
}

export const SERVICE_TESTS: Record<string, ServiceTestDef[]> = {
  TIP: [
    { id: "virustotal", label: "VirusTotal", overrides: { api_key: "virustotal_api_key" } },
    { id: "abuseipdb", label: "AbuseIPDB", overrides: { api_key: "abuseipdb_api_key" } },
    { id: "otx", label: "OTX", overrides: { api_key: "otx_api_key" } },
    { id: "threatfox", label: "ThreatFox", overrides: { api_key: "threatfox_api_key" } },
    { id: "nvd", label: "NVD", overrides: { api_key: "nvd_api_key" } },
  ],
  SIEM: [{ id: "wazuh", label: "Wazuh", overrides: { endpoint_url: "siem_manager_url", username: "siem_user", api_key: "siem_password" } }],
  AI: [{ id: "openrouter", label: "OpenRouter", integrationKey: "ai", overrides: { api_key: "openrouter_api_key" } }],
  IAM: [{ id: "okta", label: "Okta", overrides: { endpoint_url: "okta_domain", api_key: "okta_api_token" } }],
  ITSM: [
    { id: "jira", label: "Jira", overrides: { endpoint_url: "jira_base_url", username: "jira_email", api_key: "jira_api_token" } },
    { id: "slack", label: "Slack", overrides: { endpoint_url: "slack_webhook_url" } },
  ],
};
