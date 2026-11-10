"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Sliders,
  Radio,
  Database,
  KeyRound,
  Bell,
  ShieldCheck,
  Bot,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Save,
  Eye,
  EyeOff,
  Activity,
  XCircle,
  Lock,
  Trash2,
  Undo2,
  FlaskConical
} from "lucide-react";
import { api } from "@/lib/api";
import { isAdmin, isSecEngOrAdmin } from "@/lib/roles";
import { ConfigEntry, ConfigUpdateItem, SystemConfigGroup, TestConnectionResult } from "@/lib/types";
import { useAuth } from "@/components/AuthGate";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";

// Categories and keys follow backend integration_config.INTEGRATION_KEYS / DEFAULT_CONFIGS.

type FieldKind = "secret" | "text" | "url" | "bool" | "list" | "number" | "select";

interface FieldDef {
  key: string;
  label: string;
  kind: FieldKind;
  placeholder?: string;
  help?: string;
  options?: Array<{ value: string; label: string; help: string }>;
  defaultValue?: string;
}

type ServiceId = "virustotal" | "abuseipdb" | "otx" | "threatfox" | "nvd" | "wazuh" | "okta" | "jira" | "slack";

interface ServiceDef {
  id: ServiceId;
  label: string;
  /** Which form fields are sent as test overrides when they hold unsaved values. */
  overrides: { api_key?: string; endpoint_url?: string; username?: string };
}

interface SectionDef {
  category: string;
  title: string;
  description: string;
  icon: React.ElementType;
  fields: FieldDef[];
  services: ServiceDef[];
}

const AGENT_AUTONOMY_OPTIONS = [
  { value: "recommend_only", label: "Recommend only", help: "Every agent proposal waits for an analyst decision." },
  { value: "low_impact", label: "Low impact", help: "Low-impact actions run automatically when confidence meets the minimum; everything else waits for approval." },
  { value: "policy", label: "Policy", help: "Low- and medium-impact actions run automatically when confidence meets the minimum. High-impact actions always need approval." },
];

const SECTIONS: SectionDef[] = [
  {
    category: "TIP",
    title: "Threat Intelligence Providers",
    description: "IOC reputation lookups. Providers without a key report \"not configured\"; no score is ever invented for them.",
    icon: Radio,
    fields: [
      { key: "virustotal_api_key", label: "VirusTotal API key", kind: "secret" },
      { key: "abuseipdb_api_key", label: "AbuseIPDB API key", kind: "secret" },
      { key: "otx_api_key", label: "AlienVault OTX API key", kind: "secret" },
      { key: "threatfox_api_key", label: "ThreatFox Auth-Key", kind: "secret" },
      { key: "nvd_api_key", label: "NIST NVD API key", kind: "secret", help: "Optional: NVD works without a key at a lower rate limit." },
    ],
    services: [
      { id: "virustotal", label: "VirusTotal", overrides: { api_key: "virustotal_api_key" } },
      { id: "abuseipdb", label: "AbuseIPDB", overrides: { api_key: "abuseipdb_api_key" } },
      { id: "otx", label: "OTX", overrides: { api_key: "otx_api_key" } },
      { id: "threatfox", label: "ThreatFox", overrides: { api_key: "threatfox_api_key" } },
      { id: "nvd", label: "NVD", overrides: { api_key: "nvd_api_key" } },
    ],
  },
  {
    category: "SIEM",
    title: "SIEM (Wazuh Manager API)",
    description: "Wazuh manager REST API used for read-only checks and active response. Alerts themselves arrive through the authenticated webhook.",
    icon: Database,
    fields: [
      { key: "siem_manager_url", label: "Wazuh Manager API URL", kind: "url", placeholder: "https://wazuh-manager.example.org:55000" },
      { key: "siem_user", label: "API username", kind: "text" },
      { key: "siem_password", label: "API password", kind: "secret" },
      { key: "siem_verify_tls", label: "Verify TLS certificate", kind: "bool", defaultValue: "true", help: "Turn off only for lab managers with self-signed certificates." },
    ],
    services: [
      { id: "wazuh", label: "Wazuh", overrides: { endpoint_url: "siem_manager_url", username: "siem_user", api_key: "siem_password" } },
    ],
  },
  {
    category: "IAM",
    title: "Identity Provider (Okta)",
    description: "Used by disable_account, revoke_user_sessions and force_password_reset.",
    icon: KeyRound,
    fields: [
      { key: "okta_domain", label: "Okta domain", kind: "text", placeholder: "your-org.okta.com" },
      { key: "okta_api_token", label: "Okta API token", kind: "secret" },
    ],
    services: [
      { id: "okta", label: "Okta", overrides: { endpoint_url: "okta_domain", api_key: "okta_api_token" } },
    ],
  },
  {
    category: "ITSM",
    title: "Ticketing & Notifications",
    description: "Jira tickets (REST API or an automation webhook) and Slack notifications for create_ticket / send_notification.",
    icon: Bell,
    fields: [
      { key: "jira_base_url", label: "Jira base URL", kind: "url", placeholder: "https://your-org.atlassian.net" },
      { key: "jira_email", label: "Jira account email", kind: "text" },
      { key: "jira_api_token", label: "Jira API token", kind: "secret" },
      { key: "jira_project_key", label: "Jira project key", kind: "text", placeholder: "SEC" },
      { key: "jira_webhook_url", label: "Jira automation webhook URL (alternative to the REST API)", kind: "secret" },
      { key: "slack_webhook_url", label: "Slack incoming webhook URL", kind: "secret" },
    ],
    services: [
      { id: "jira", label: "Jira", overrides: { endpoint_url: "jira_base_url", username: "jira_email", api_key: "jira_api_token" } },
      { id: "slack", label: "Slack", overrides: { endpoint_url: "slack_webhook_url" } },
    ],
  },
  {
    category: "ORCHESTRATION",
    title: "Orchestration & Safety Guards",
    description: "Global switches and assets that automated actors (playbooks, AI agent) must never act on.",
    icon: ShieldCheck,
    fields: [
      {
        key: "simulation_mode",
        label: "Simulation mode",
        kind: "bool",
        defaultValue: "true",
        help: "On: actions on connectors that are not configured are recorded as SIMULATED (nothing changes on real systems) and lab threat-intel fixtures answer for documentation IPs and demo IOCs. Off: unconfigured actions are SKIPPED. Turn off in production.",
      },
      {
        key: "hotl_enabled",
        label: "HOTL autonomous containment",
        kind: "bool",
        defaultValue: "true",
        help: "On: HOTL playbooks may contain automatically when there is real evidence and policy allows it. Off: every action waits for analyst approval.",
      },
      { key: "protected_hosts", label: "Protected hosts", kind: "list", placeholder: "dc01\nprod-db-01", help: "One per line (or comma separated). Automated actors are denied; analysts are warned." },
      { key: "protected_users", label: "Protected users", kind: "list", placeholder: "abunemah\nbreakglass-admin" },
      { key: "protected_ips", label: "Protected IPs / CIDR ranges", kind: "list", placeholder: "10.0.0.1\n192.168.10.0/24" },
    ],
    services: [],
  },
  {
    category: "AGENT",
    title: "AI Agent Policy",
    description: "Limits for the external AI triage agent. The policy engine checks every proposed action against these settings.",
    icon: Bot,
    fields: [
      { key: "agent_autonomy", label: "Agent autonomy", kind: "select", defaultValue: "recommend_only", options: AGENT_AUTONOMY_OPTIONS },
      { key: "agent_min_confidence", label: "Minimum confidence for automatic execution (0 – 1)", kind: "number", defaultValue: "0.85" },
    ],
    services: [],
  },
];

const fieldId = (category: string, key: string) => `${category}.${key}`;

/** Stored value of a non-secret field; an empty stored value falls back to the backend default. */
function savedValue(config: SystemConfigGroup | null, category: string, field: FieldDef): string {
  const entry = config?.[category]?.[field.key];
  if (entry && !entry.is_secret && typeof entry.value === "string" && (entry.value !== "" || !field.defaultValue)) {
    return entry.value;
  }
  return field.defaultValue ?? "";
}

function testStatusStyle(result: TestConnectionResult): { className: string; icon: React.ElementType } {
  const s = (result.status || "").toLowerCase();
  if (result.is_connected || s === "connected") return { className: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400", icon: CheckCircle2 };
  if (s.startsWith("not configured")) return { className: "bg-slate-800/60 border-slate-700 text-slate-400", icon: Sliders };
  if (s.startsWith("configured")) return { className: "bg-blue-500/10 border-blue-500/20 text-blue-300", icon: CheckCircle2 };
  if (s === "unreachable") return { className: "bg-amber-500/10 border-amber-500/20 text-amber-400", icon: AlertTriangle };
  return { className: "bg-rose-500/10 border-rose-500/20 text-rose-400", icon: XCircle };
}

export default function ConfigurationPage() {
  const { user } = useAuth();
  const { status: runtime, refresh: refreshRuntime } = useRuntimeStatus();
  const canView = isSecEngOrAdmin(user);
  const canEdit = isAdmin(user);

  const [config, setConfig] = useState<SystemConfigGroup | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [clears, setClears] = useState<Record<string, boolean>>({});
  const [visibleSecrets, setVisibleSecrets] = useState<Record<string, boolean>>({});
  const [testResults, setTestResults] = useState<Partial<Record<ServiceId, TestConnectionResult>>>({});
  const [testingId, setTestingId] = useState<ServiceId | null>(null);
  const [saving, setSaving] = useState<boolean>(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const resetForm = useCallback((data: SystemConfigGroup | null) => {
    const initial: Record<string, string> = {};
    SECTIONS.forEach((section) =>
      section.fields.forEach((field) => {
        initial[fieldId(section.category, field.key)] = field.kind === "secret" ? "" : savedValue(data, section.category, field);
      })
    );
    setValues(initial);
    setClears({});
  }, []);

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getConfigurations();
      setConfig(data);
      resetForm(data);
      setLoadError(null);
    } catch (err: any) {
      setLoadError(err.message || "Could not load configuration.");
    } finally {
      setLoading(false);
    }
  }, [resetForm]);

  useEffect(() => {
    if (canView) loadConfig();
    else setLoading(false);
  }, [canView, loadConfig]);

  const entryOf = (category: string, key: string): ConfigEntry | undefined => config?.[category]?.[key];

  const isDirty = useCallback(
    (category: string, field: FieldDef): boolean => {
      const id = fieldId(category, field.key);
      if (field.kind === "secret") return Boolean(values[id]) || Boolean(clears[id]);
      return (values[id] ?? "") !== savedValue(config, category, field);
    },
    [values, clears, config]
  );

  const dirtyCount = useMemo(
    () => SECTIONS.reduce((n, s) => n + s.fields.filter((f) => isDirty(s.category, f)).length, 0),
    [isDirty]
  );

  const setValue = (category: string, key: string, value: string) => {
    const id = fieldId(category, key);
    setValues((prev) => ({ ...prev, [id]: value }));
    if (value) setClears((prev) => ({ ...prev, [id]: false }));
  };

  const toggleClear = (category: string, key: string) => {
    const id = fieldId(category, key);
    setClears((prev) => ({ ...prev, [id]: !prev[id] }));
    setValues((prev) => ({ ...prev, [id]: "" }));
  };

  const validate = (): string | null => {
    const conf = values[fieldId("AGENT", "agent_min_confidence")];
    if (conf !== undefined && conf !== "") {
      const n = Number(conf);
      if (!Number.isFinite(n) || n < 0 || n > 1) return "Minimum confidence must be a number between 0 and 1.";
    }
    return null;
  };

  const handleSave = async () => {
    setSaveMsg(null);
    setSaveError(null);
    const validationError = validate();
    if (validationError) {
      setSaveError(validationError);
      return;
    }

    const items: ConfigUpdateItem[] = [];
    SECTIONS.forEach((section) =>
      section.fields.forEach((field) => {
        if (!isDirty(section.category, field)) return;
        const id = fieldId(section.category, field.key);
        const isSecret = field.kind === "secret";
        items.push({
          category: section.category,
          key_name: field.key,
          key_value: values[id] ?? "",
          is_secret: isSecret,
          ...(isSecret && clears[id] ? { clear: true } : {}),
        });
      })
    );

    if (items.length === 0) {
      setSaveMsg("No changes to save.");
      return;
    }

    setSaving(true);
    try {
      await api.updateConfigurations(items);
      setSaveMsg(`Saved ${items.length} setting${items.length === 1 ? "" : "s"}. Secrets are stored server-side and never sent back to the browser.`);
      setTestResults({});
      await loadConfig();
      await refreshRuntime();
    } catch (err: any) {
      setSaveError(`Save failed: ${err.message || "request failed"}`);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async (section: SectionDef, service: ServiceDef) => {
    setTestingId(service.id);
    const overrides: { api_key?: string; endpoint_url?: string; username?: string } = {};
    (Object.keys(service.overrides) as Array<keyof ServiceDef["overrides"]>).forEach((param) => {
      const key = service.overrides[param];
      if (!key) return;
      const field = section.fields.find((f) => f.key === key);
      if (field && isDirty(section.category, field) && values[fieldId(section.category, key)]) {
        overrides[param] = values[fieldId(section.category, key)];
      }
    });
    try {
      const res = await api.testConnection(section.category, service.id, Object.keys(overrides).length ? overrides : undefined);
      setTestResults((prev) => ({ ...prev, [service.id]: res }));
    } catch (err: any) {
      setTestResults((prev) => ({
        ...prev,
        [service.id]: {
          status: "Error",
          is_connected: false,
          service_name: service.label,
          category: section.category,
          message: err.message || "The connection test request failed.",
        },
      }));
    } finally {
      setTestingId(null);
    }
  };

  if (!canView) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] text-center px-4">
        <div className="h-16 w-16 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 mb-4">
          <Lock className="h-8 w-8" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Access Restricted</h2>
        <p className="text-sm text-slate-400 max-w-md">
          Integration settings are available to administrators and security engineers. Your role is <b>{user?.role || "unknown"}</b>.
        </p>
      </div>
    );
  }

  const renderField = (section: SectionDef, field: FieldDef) => {
    const id = fieldId(section.category, field.key);
    const value = values[id] ?? "";
    const entry = entryOf(section.category, field.key);
    const dirty = isDirty(section.category, field);
    const disabled = !canEdit;
    const inputClass =
      "w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 disabled:opacity-60";

    const label = (
      <label className="text-[11px] font-semibold text-slate-300 flex items-center gap-2" htmlFor={id}>
        <span>{field.label}</span>
        {dirty && <span className="text-[10px] text-amber-400 font-bold">unsaved</span>}
      </label>
    );

    if (field.kind === "secret") {
      const isSet = Boolean(entry?.is_set);
      const willClear = Boolean(clears[id]);
      const visible = Boolean(visibleSecrets[id]);
      return (
        <div key={field.key} className="space-y-1">
          <div className="flex items-center justify-between gap-2">
            {label}
            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
              willClear
                ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
                : isSet
                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                : "bg-slate-800 text-slate-500 border-slate-700"
            }`}>
              {willClear ? "Will be cleared" : isSet ? `Set (${entry?.preview || "••••"})` : "Not set"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <input
                id={id}
                type={visible ? "text" : "password"}
                autoComplete="off"
                value={value}
                disabled={disabled || willClear}
                onChange={(e) => setValue(section.category, field.key, e.target.value)}
                placeholder={isSet ? "Leave blank to keep the stored value" : "Not set — enter a value"}
                className={inputClass + " pr-8"}
              />
              <button
                type="button"
                onClick={() => setVisibleSecrets((prev) => ({ ...prev, [id]: !prev[id] }))}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                title={visible ? "Hide" : "Show what you typed"}
              >
                {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </button>
            </div>
            {canEdit && (isSet || willClear) && (
              <button
                type="button"
                onClick={() => toggleClear(section.category, field.key)}
                className={`flex items-center gap-1 px-2 py-2 rounded-lg border text-[11px] font-semibold transition ${
                  willClear
                    ? "bg-slate-800 border-slate-700 text-slate-300 hover:text-white"
                    : "bg-slate-900 border-slate-800 text-rose-400 hover:bg-rose-500/10"
                }`}
                title={willClear ? "Keep the stored value" : "Remove the stored value on save"}
              >
                {willClear ? <Undo2 className="h-3.5 w-3.5" /> : <Trash2 className="h-3.5 w-3.5" />}
                <span>{willClear ? "Undo" : "Clear"}</span>
              </button>
            )}
          </div>
          {field.help && <p className="text-[10px] text-slate-500">{field.help}</p>}
        </div>
      );
    }

    if (field.kind === "bool") {
      const on = value === "true";
      return (
        <div key={field.key} className="space-y-1">
          <div className="flex items-center justify-between gap-3">
            {label}
            <button
              id={id}
              type="button"
              role="switch"
              aria-checked={on}
              disabled={disabled}
              onClick={() => setValue(section.category, field.key, on ? "false" : "true")}
              className={`relative inline-flex h-5 w-10 flex-shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ${
                on ? "bg-emerald-500" : "bg-slate-700"
              } ${disabled ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
            >
              <span className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow transition duration-200 ${on ? "translate-x-5" : "translate-x-0"}`} />
            </button>
          </div>
          {field.help && <p className="text-[10px] text-slate-500 leading-relaxed">{field.help}</p>}
        </div>
      );
    }

    if (field.kind === "list") {
      return (
        <div key={field.key} className="space-y-1">
          {label}
          <textarea
            id={id}
            rows={3}
            value={value}
            disabled={disabled}
            onChange={(e) => setValue(section.category, field.key, e.target.value)}
            placeholder={field.placeholder}
            className={inputClass + " resize-y"}
          />
          {field.help && <p className="text-[10px] text-slate-500">{field.help}</p>}
        </div>
      );
    }

    if (field.kind === "select") {
      const selected = field.options?.find((o) => o.value === value);
      return (
        <div key={field.key} className="space-y-1">
          {label}
          <select
            id={id}
            value={value}
            disabled={disabled}
            onChange={(e) => setValue(section.category, field.key, e.target.value)}
            className={inputClass}
          >
            {field.options?.map((o) => (
              <option key={o.value} value={o.value}>{o.label} ({o.value})</option>
            ))}
          </select>
          {selected && <p className="text-[10px] text-slate-500">{selected.help}</p>}
        </div>
      );
    }

    return (
      <div key={field.key} className="space-y-1">
        {label}
        <input
          id={id}
          type={field.kind === "number" ? "number" : field.kind === "url" ? "url" : "text"}
          step={field.kind === "number" ? "0.01" : undefined}
          min={field.kind === "number" ? 0 : undefined}
          max={field.kind === "number" ? 1 : undefined}
          value={value}
          disabled={disabled}
          onChange={(e) => setValue(section.category, field.key, e.target.value)}
          placeholder={field.placeholder || "Not set"}
          className={inputClass}
        />
        {field.help && <p className="text-[10px] text-slate-500">{field.help}</p>}
      </div>
    );
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center space-x-3 mb-1">
            <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2.5">
              <Sliders className="h-6 w-6 text-blue-500" />
              Integrations & Platform Settings
            </h1>
            {runtime?.simulation_mode && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-fuchsia-500/20 text-fuchsia-300 font-bold border border-fuchsia-500/30 flex items-center gap-1">
                <FlaskConical className="h-3 w-3" />
                SIMULATION MODE
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            Values saved here override environment variables. Secrets are write-only: the server only returns whether a secret is set and its last four characters.
            Connection tests make a real, read-only request with the stored settings (or the values you typed but have not saved yet).
          </p>
        </div>

        {canEdit ? (
          <button
            onClick={handleSave}
            disabled={saving || loading}
            className="flex items-center justify-center space-x-2 px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-xl shadow-blue-600/30 transition disabled:opacity-50"
          >
            <Save className="h-4 w-4" />
            <span>{saving ? "Saving..." : dirtyCount ? `Save ${dirtyCount} change${dirtyCount === 1 ? "" : "s"}` : "Save changes"}</span>
          </button>
        ) : (
          <div className="flex items-center space-x-1.5 px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-medium text-slate-400">
            <Lock className="h-3.5 w-3.5 text-amber-400" />
            <span>Read-only: only administrators can change settings or run tests</span>
          </div>
        )}
      </div>

      {loadError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          <span>{loadError}</span>
        </div>
      )}
      {saveError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          <span>{saveError}</span>
        </div>
      )}
      {saveMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center space-x-2">
          <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
          <span>{saveMsg}</span>
        </div>
      )}

      {loading && !config ? (
        <div className="flex flex-col items-center justify-center py-20 space-y-3">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
          <p className="text-sm text-slate-400">Loading configuration...</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {SECTIONS.map((section) => {
            const Icon = section.icon;
            return (
              <div
                key={section.category}
                className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col shadow-lg hover:border-slate-700/80 transition space-y-5"
              >
                <div className="space-y-2">
                  <div className="flex items-center space-x-3">
                    <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
                      <Icon className="h-5 w-5 text-blue-400" />
                    </div>
                    <div>
                      <h3 className="font-bold text-base text-white tracking-wide">{section.title}</h3>
                      <span className="text-[10px] font-mono text-slate-500">Category: {section.category}</span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{section.description}</p>
                </div>

                <div className="space-y-3.5 bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
                  {section.fields.map((field) => renderField(section, field))}
                </div>

                {section.services.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80 space-y-2">
                    <span className="text-[11px] text-slate-500 block">Connection tests</span>
                    {section.services.map((service) => {
                      const result = testResults[service.id];
                      const configured = runtime?.integrations?.[service.id];
                      const style = result ? testStatusStyle(result) : null;
                      const ResultIcon = style?.icon;
                      return (
                        <div key={service.id} className="space-y-1.5">
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2 text-xs">
                              <span className="font-semibold text-slate-200">{service.label}</span>
                              {configured !== undefined && (
                                <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                                  configured ? "bg-blue-500/10 text-blue-300 border-blue-500/20" : "bg-slate-800 text-slate-500 border-slate-700"
                                }`}>
                                  {configured ? "Configured" : "Not configured"}
                                </span>
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => handleTest(section, service)}
                              disabled={!canEdit || testingId !== null}
                              title={canEdit ? `Run a read-only authentication check against ${service.label}` : "Administrators only"}
                              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 text-xs font-semibold transition disabled:opacity-50"
                            >
                              <Activity className={`h-3.5 w-3.5 text-blue-400 ${testingId === service.id ? "animate-spin" : ""}`} />
                              <span>{testingId === service.id ? "Testing..." : "Test"}</span>
                            </button>
                          </div>
                          {result && style && ResultIcon && (
                            <div className={`p-2.5 rounded-lg border text-xs ${style.className}`}>
                              <div className="flex items-start space-x-2">
                                <ResultIcon className="h-4 w-4 flex-shrink-0 mt-0.5" />
                                <div className="space-y-0.5">
                                  <div className="font-bold flex items-center gap-2">
                                    <span>{result.status}</span>
                                    {result.health && result.health !== result.status && (
                                      <span className="font-normal opacity-80">· {result.health}</span>
                                    )}
                                    {typeof result.latency_ms === "number" && result.latency_ms > 0 && (
                                      <span className="font-mono text-[10px] opacity-75">({result.latency_ms}ms)</span>
                                    )}
                                  </div>
                                  <p className="text-[11px] opacity-90 leading-tight">{result.message}</p>
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
