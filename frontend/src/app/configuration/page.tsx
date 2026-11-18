"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, Bot, CheckCircle2, Database, Eye, EyeOff, FlaskConical, KeyRound, Lock, Radio, Save, ShieldCheck, Sliders, Trash2, Undo2,
  AlertTriangle, XCircle, Bell,
} from "lucide-react";
import { api } from "@/lib/api";
import { ApiError, describeError, errorBlockers } from "@/lib/errors";
import {
  FIELD_META, SERVICE_TESTS, categoryMeta, fieldLabel, inferFieldKind, normalizeBool, sortedCategories, validateConfigValue, FieldKind,
} from "@/lib/configRules";
import { canAdminister, canViewConfig } from "@/lib/roles";
import { ConfigEntry, ConfigUpdateItem, SystemConfigGroup, TestConnectionResult } from "@/lib/types";
import { useResource } from "@/hooks/useResource";
import { useAuth } from "@/components/AuthGate";
import { useConfirm } from "@/components/ConfirmDialog";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";
import { AccessDenied, ErrorState, InlineNotice, LoadingState } from "@/components/StateViews";
import { useToast } from "@/components/Toast";

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  TIP: Radio, SIEM: Database, IAM: KeyRound, ITSM: Bell, ORCHESTRATION: ShieldCheck, AGENT: Bot, AI: Bot,
};

/** Settings whose change alters what automation may do: confirmed in plain language before saving. */
const HIGH_IMPACT: Record<string, (next: string) => string | null> = {
  simulation_mode: (n) =>
    n === "false"
      ? "Simulation mode OFF: connectors that are configured will act on real systems, and unconfigured actions are skipped instead of rehearsed."
      : "Simulation mode ON: actions are only rehearsed and recorded as SIMULATED. Nothing is contained.",
  hotl_enabled: (n) =>
    n === "true"
      ? "HOTL ON: HOTL playbooks may contain automatically when there is real evidence and policy allows it."
      : "HOTL OFF: every containment action waits for an analyst.",
  agent_autonomy: (n) => `AI agent autonomy becomes "${n}": ${n === "recommend_only" ? "every proposal waits for an analyst." : "some AI actions may run without a human decision."}`,
  agent_min_confidence: (n) => `Minimum confidence for automatic AI execution becomes ${n || "the default"}.`,
  ai_enabled: (n) => (n === "true" ? "Built-in AI triage ON: alert summaries are sent to the configured model provider." : "Built-in AI triage OFF: no alert data is sent to a model."),
  ai_send_raw_payload: (n) =>
    n === "true"
      ? "The FULL raw alert payload (possible usernames, hostnames, credentials) will be sent to a third-party model provider."
      : "Only a redacted summary of each alert will be sent to the model provider.",
  require_mfa_for_admin: (n) => (n === "true" ? "Administrators without MFA must enrol before using the console." : "Administrators will no longer be forced to use MFA."),
  simulation_confirmed_in_production: (n) => (n === "true" ? "You acknowledge that simulation mode is intended although real connectors are configured." : null),
};

const fieldId = (category: string, key: string) => `${category}.${key}`;

function entryValue(entry: ConfigEntry | undefined, kind: FieldKind): string {
  if (!entry || entry.is_secret) return "";
  const v = typeof entry.value === "string" ? entry.value : "";
  if (kind === "bool") return normalizeBool(v) ?? (v === "" ? "false" : v);
  return v;
}

function SourceBadge({ entry }: { entry: ConfigEntry | undefined }) {
  if (!entry) return null;
  const source = entry.source;
  if (source === "environment") {
    return (
      <span className="text-[10px] px-1.5 py-0.5 rounded border bg-indigo-500/10 text-indigo-300 border-indigo-500/30" title="The value comes from a server environment variable. A value saved here would take precedence.">
        set via environment{entry.env_var ? ` (${entry.env_var})` : ""}
      </span>
    );
  }
  if (source === "database") {
    return <span className="text-[10px] px-1.5 py-0.5 rounded border bg-blue-500/10 text-blue-300 border-blue-500/30">saved in settings</span>;
  }
  if (source === "default") {
    return <span className="text-[10px] px-1.5 py-0.5 rounded border bg-slate-800 text-slate-400 border-slate-700">default</span>;
  }
  return null;
}

function testStyle(result: TestConnectionResult): { className: string; icon: React.ElementType } {
  const s = (result.status || "").toLowerCase();
  if (result.is_connected || s === "connected") return { className: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400", icon: CheckCircle2 };
  if (s.startsWith("not configured")) return { className: "bg-slate-800/60 border-slate-700 text-slate-400", icon: Sliders };
  if (s.startsWith("configured")) return { className: "bg-blue-500/10 border-blue-500/20 text-blue-300", icon: CheckCircle2 };
  if (s === "unreachable" || s.includes("rate")) return { className: "bg-amber-500/10 border-amber-500/20 text-amber-400", icon: AlertTriangle };
  return { className: "bg-rose-500/10 border-rose-500/20 text-rose-400", icon: XCircle };
}

export default function ConfigurationPage() {
  const { user } = useAuth();
  const { status: runtime, refresh: refreshRuntime } = useRuntimeStatus();
  const toast = useToast();
  const confirm = useConfirm();
  const canView = canViewConfig(user);
  const canEdit = canAdminister(user);

  const fetcher = useCallback(() => api.getConfigurations(), []);
  const resource = useResource<SystemConfigGroup>(fetcher, { enabled: canView });
  const config = resource.data;

  const [values, setValues] = useState<Record<string, string>>({});
  const [clears, setClears] = useState<Record<string, boolean>>({});
  const [shown, setShown] = useState<Record<string, boolean>>({});
  const [tests, setTests] = useState<Record<string, TestConnectionResult>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<{ message: string; blockers: string[] } | null>(null);

  // Reset the form whenever fresh data arrives (initial load, after a save).
  useEffect(() => {
    if (!config) return;
    const initial: Record<string, string> = {};
    Object.entries(config).forEach(([category, entries]) =>
      Object.entries(entries).forEach(([key, entry]) => {
        const kind = FIELD_META[key]?.kind ?? inferFieldKind(key, entry);
        initial[fieldId(category, key)] = entryValue(entry, kind);
      })
    );
    setValues(initial);
    setClears({});
  }, [config]);

  const categories = useMemo(() => (config ? sortedCategories(Object.keys(config)) : []), [config]);

  const kindOf = useCallback(
    (key: string, entry: ConfigEntry | undefined): FieldKind => FIELD_META[key]?.kind ?? inferFieldKind(key, entry),
    []
  );

  const isDirty = useCallback(
    (category: string, key: string): boolean => {
      const entry = config?.[category]?.[key];
      const id = fieldId(category, key);
      const kind = kindOf(key, entry);
      if (kind === "secret") return Boolean(values[id]) || Boolean(clears[id]);
      const current = values[id] ?? "";
      const saved = entryValue(entry, kind);
      return current.trim() !== saved.trim();
    },
    [config, values, clears, kindOf]
  );

  const errors = useMemo(() => {
    const out: Record<string, string> = {};
    if (!config) return out;
    Object.entries(config).forEach(([category, entries]) =>
      Object.entries(entries).forEach(([key, entry]) => {
        if (entry.is_secret || !isDirty(category, key)) return;
        const message = validateConfigValue(key, values[fieldId(category, key)] ?? "");
        if (message) out[fieldId(category, key)] = message;
      })
    );
    return out;
  }, [config, values, isDirty]);

  const dirtyIds = useMemo(() => {
    const ids: Array<{ category: string; key: string }> = [];
    if (!config) return ids;
    Object.entries(config).forEach(([category, entries]) =>
      Object.keys(entries).forEach((key) => {
        if (isDirty(category, key)) ids.push({ category, key });
      })
    );
    return ids;
  }, [config, isDirty]);

  // Warn before leaving with unsaved edits.
  useEffect(() => {
    if (dirtyIds.length === 0) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirtyIds.length]);

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

  const buildItems = (): ConfigUpdateItem[] => {
    const items: ConfigUpdateItem[] = [];
    dirtyIds.forEach(({ category, key }) => {
      const entry = config?.[category]?.[key];
      const kind = kindOf(key, entry);
      const id = fieldId(category, key);
      const isSecret = Boolean(entry?.is_secret) || kind === "secret";
      let value = values[id] ?? "";
      if (kind === "bool") value = normalizeBool(value) ?? value;
      items.push({
        category,
        key_name: key,
        key_value: isSecret ? value : value.trim(),
        is_secret: isSecret,
        ...(isSecret && clears[id] ? { clear: true } : {}),
      });
    });
    return items;
  };

  const save = async () => {
    setSaveError(null);
    if (Object.keys(errors).length > 0) {
      setSaveError({ message: "Fix the highlighted fields before saving.", blockers: [] });
      return;
    }
    const items = buildItems();
    if (items.length === 0) {
      toast.info("No changes to save.");
      return;
    }
    const consequences: string[] = [];
    items.forEach((item) => {
      const rule = HIGH_IMPACT[item.key_name];
      const text = rule?.(item.key_value);
      if (text) consequences.push(text);
      if (item.is_secret) consequences.push(item.clear ? `${fieldLabel(item.key_name)} will be removed.` : `${fieldLabel(item.key_name)} will be replaced (the new value is never shown again).`);
    });
    const ok = await confirm({
      title: `Save ${items.length} setting${items.length === 1 ? "" : "s"}?`,
      message: consequences.length ? "Review what changes before you apply it:" : "The listed settings are saved and apply to new work immediately.",
      items: consequences.length ? consequences : items.map((i) => fieldLabel(i.key_name)),
      confirmLabel: "Save changes",
      tone: consequences.some((c) => !c.endsWith("never shown again).")) ? "warning" : "default",
    });
    if (!ok) return;

    setSaving(true);
    try {
      await api.updateConfigurations(items);
      toast.success(`Saved ${items.length} setting${items.length === 1 ? "" : "s"}. Secrets stay on the server and are never sent back.`);
      setTests({});
      await resource.reload();
      await refreshRuntime();
    } catch (err) {
      const blockers = errorBlockers(err);
      const message = describeError(err, "Could not save the settings.");
      setSaveError({ message: `Save failed: ${message}`, blockers });
      if (err instanceof ApiError && err.status === 409 && blockers.length) {
        await confirm({
          title: "This change was refused",
          message,
          items: blockers,
          confirmLabel: "Understood",
          hideCancel: true,
          tone: "warning",
        });
      }
    } finally {
      setSaving(false);
    }
  };

  const runTest = async (category: string, serviceId: string, label: string, overrides: { api_key?: string; endpoint_url?: string; username?: string }) => {
    setTesting(serviceId);
    const send: { api_key?: string; endpoint_url?: string; username?: string } = {};
    (Object.keys(overrides) as Array<keyof typeof overrides>).forEach((param) => {
      const key = overrides[param];
      if (!key) return;
      const id = fieldId(category, key);
      if (isDirty(category, key) && values[id]) send[param] = values[id];
    });
    try {
      const res = await api.testConnection(category, serviceId, Object.keys(send).length ? send : undefined);
      setTests((prev) => ({ ...prev, [serviceId]: res }));
    } catch (err) {
      setTests((prev) => ({
        ...prev,
        [serviceId]: { status: "Error", is_connected: false, service_name: label, category, message: describeError(err, "The connection test failed.") },
      }));
    } finally {
      setTesting(null);
    }
  };

  if (!canView) {
    return (
      <AccessDenied title="Access restricted">
        Integration settings are available to administrators and security engineers. Your role is <b>{user?.role || "unknown"}</b>.
      </AccessDenied>
    );
  }

  const inputClass =
    "w-full bg-slate-900 border rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60";

  const renderField = (category: string, key: string, entry: ConfigEntry) => {
    const id = fieldId(category, key);
    const kind = kindOf(key, entry);
    const meta = FIELD_META[key];
    const value = values[id] ?? "";
    const dirty = isDirty(category, key);
    const error = errors[id];
    const disabled = !canEdit;
    const describedBy = [meta?.help ? `${id}-help` : "", error ? `${id}-error` : ""].filter(Boolean).join(" ") || undefined;
    const borderClass = error ? "border-rose-500" : "border-slate-800";

    const head = (
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <label className="text-[11px] font-semibold text-slate-300 flex items-center gap-2" htmlFor={id}>
          <span>{fieldLabel(key)}</span>
          {dirty && <span className="text-[10px] text-amber-400 font-bold">unsaved</span>}
        </label>
        <SourceBadge entry={entry} />
      </div>
    );
    const foot = (
      <>
        {meta?.help && <p id={`${id}-help`} className="text-[10px] text-slate-500 leading-relaxed">{meta.help}</p>}
        {error && <p id={`${id}-error`} role="alert" className="text-[11px] text-rose-400">{error}</p>}
      </>
    );

    if (kind === "secret") {
      const isSet = Boolean(entry.is_set);
      const fromEnv = entry.source === "environment";
      const willClear = Boolean(clears[id]);
      const visible = Boolean(shown[id]);
      return (
        <div key={key} className="space-y-1">
          {head}
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <input
                id={id}
                type={visible ? "text" : "password"}
                autoComplete="off"
                value={value}
                disabled={disabled || willClear}
                onChange={(e) => setValue(category, key, e.target.value)}
                placeholder={willClear ? "Will be cleared on save" : isSet ? "Set. Leave blank to keep it" : "Not set. Enter a value"}
                aria-describedby={describedBy}
                className={`${inputClass} ${borderClass} pr-8`}
              />
              <button
                type="button"
                onClick={() => setShown((prev) => ({ ...prev, [id]: !prev[id] }))}
                aria-label={visible ? `Hide what you typed for ${fieldLabel(key)}` : `Show what you typed for ${fieldLabel(key)}`}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
              >
                {visible ? <EyeOff className="h-3.5 w-3.5" aria-hidden="true" /> : <Eye className="h-3.5 w-3.5" aria-hidden="true" />}
              </button>
            </div>
            {canEdit && isSet && !fromEnv && (
              <button
                type="button"
                onClick={() => toggleClear(category, key)}
                className={`flex items-center gap-1 px-2 py-2 rounded-lg border text-[11px] font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  willClear ? "bg-slate-800 border-slate-700 text-slate-300" : "bg-slate-900 border-slate-800 text-rose-400 hover:bg-rose-500/10"
                }`}
              >
                {willClear ? <Undo2 className="h-3.5 w-3.5" aria-hidden="true" /> : <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />}
                <span>{willClear ? "Undo" : "Clear"}</span>
              </button>
            )}
          </div>
          <p className="text-[10px] text-slate-500">
            {willClear ? "The stored value will be removed." : isSet ? `Currently set${entry.preview ? ` (${entry.preview})` : ""}; the value is never shown.` : "Not set."}
            {fromEnv && !willClear ? " A value saved here would override the environment variable." : ""}
          </p>
          {foot}
        </div>
      );
    }

    if (kind === "bool") {
      const on = normalizeBool(value) === "true";
      return (
        <div key={key} className="space-y-1">
          <div className="flex items-center justify-between gap-3">
            <div className="flex-1 min-w-0">{head}</div>
            <button
              id={id}
              type="button"
              role="switch"
              aria-checked={on}
              aria-describedby={describedBy}
              disabled={disabled}
              onClick={() => setValue(category, key, on ? "false" : "true")}
              className={`relative inline-flex h-5 w-10 flex-shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${on ? "bg-emerald-500" : "bg-slate-700"} ${disabled ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
            >
              <span className="sr-only">{on ? "On" : "Off"}</span>
              <span aria-hidden="true" className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow transition ${on ? "translate-x-5" : "translate-x-0"}`} />
            </button>
          </div>
          {foot}
        </div>
      );
    }

    if (kind === "list") {
      return (
        <div key={key} className="space-y-1">
          {head}
          <textarea id={id} rows={3} value={value} disabled={disabled} aria-invalid={Boolean(error)} aria-describedby={describedBy} onChange={(e) => setValue(category, key, e.target.value)} placeholder={meta?.placeholder} className={`${inputClass} ${borderClass} resize-y`} />
          {foot}
        </div>
      );
    }

    if (kind === "select") {
      const options = meta?.options ?? [];
      const selected = options.find((o) => o.value === value);
      return (
        <div key={key} className="space-y-1">
          {head}
          <select id={id} value={value} disabled={disabled} aria-describedby={describedBy} onChange={(e) => setValue(category, key, e.target.value)} className={`${inputClass} ${borderClass}`}>
            {!selected && value !== "" && <option value={value}>{value}</option>}
            {options.map((o) => <option key={o.value} value={o.value}>{o.label} ({o.value})</option>)}
          </select>
          {selected?.help && <p className="text-[10px] text-slate-500">{selected.help}</p>}
          {foot}
        </div>
      );
    }

    return (
      <div key={key} className="space-y-1">
        {head}
        <input
          id={id}
          type="text"
          inputMode={kind === "number" ? "decimal" : kind === "url" ? "url" : undefined}
          value={value}
          disabled={disabled}
          aria-invalid={Boolean(error)}
          aria-describedby={describedBy}
          onChange={(e) => setValue(category, key, e.target.value)}
          placeholder={meta?.placeholder || (entry.source === "default" ? "default" : "Not set")}
          className={`${inputClass} ${borderClass}`}
        />
        {foot}
      </div>
    );
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3 mb-1 flex-wrap">
            <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2.5">
              <Sliders className="h-6 w-6 text-blue-500" aria-hidden="true" />
              Integrations &amp; platform settings
            </h1>
            {runtime?.simulation_mode && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-fuchsia-500/20 text-fuchsia-300 font-bold border border-fuchsia-500/30 flex items-center gap-1">
                <FlaskConical className="h-3 w-3" aria-hidden="true" /> SIMULATION MODE
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            Values saved here override environment variables. Secrets are write-only: the server only reports whether one is set. Connection tests make a real, read-only request with the stored settings, or with values you typed but have not saved yet.
          </p>
        </div>
        {canEdit ? (
          <button
            type="button"
            onClick={() => void save()}
            disabled={saving || resource.loading || !config}
            className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-xl shadow-blue-600/30 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
          >
            <Save className="h-4 w-4" aria-hidden="true" />
            <span>{saving ? "Saving..." : dirtyIds.length ? `Save ${dirtyIds.length} change${dirtyIds.length === 1 ? "" : "s"}` : "Save changes"}</span>
          </button>
        ) : (
          <div className="flex items-center gap-1.5 px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-medium text-slate-400">
            <Lock className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
            <span>Read-only: only administrators can change settings or run tests</span>
          </div>
        )}
      </div>

      {saveError && (
        <InlineNotice tone="error" onDismiss={() => setSaveError(null)}>
          <p>{saveError.message}</p>
          {saveError.blockers.length > 0 && (
            <ul className="list-disc pl-5 mt-1.5 space-y-0.5">
              {saveError.blockers.map((b) => <li key={b}>{b}</li>)}
            </ul>
          )}
        </InlineNotice>
      )}

      {resource.error && !config ? (
        <ErrorState title="Could not load the configuration" message={resource.error} onRetry={() => void resource.reload()} />
      ) : resource.loading && !config ? (
        <LoadingState label="Loading configuration..." />
      ) : config ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {resource.error && <div className="lg:col-span-2"><InlineNotice tone="warning">Could not refresh: {resource.error}</InlineNotice></div>}
          {categories.map((category) => {
            const meta = categoryMeta(category);
            const Icon = CATEGORY_ICONS[category] ?? Sliders;
            const entries = config[category] ?? {};
            const services = SERVICE_TESTS[category] ?? [];
            return (
              <section key={category} aria-labelledby={`cat-${category}`} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col shadow-lg space-y-5">
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
                      <Icon className="h-5 w-5 text-blue-400" aria-hidden="true" />
                    </div>
                    <div>
                      <h2 id={`cat-${category}`} className="font-bold text-base text-white tracking-wide">{meta.title}</h2>
                      <span className="text-[10px] font-mono text-slate-500">Category: {category}</span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{meta.description}</p>
                </div>

                <div className="space-y-3.5 bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
                  {Object.entries(entries).length === 0 ? (
                    <p className="text-xs text-slate-500">No settings reported for this category.</p>
                  ) : (
                    Object.entries(entries).map(([key, entry]) => renderField(category, key, entry))
                  )}
                </div>

                {services.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80 space-y-2">
                    <span className="text-[11px] text-slate-500 block">Connection tests</span>
                    {services.map((service) => {
                      const result = tests[service.id];
                      const configured = runtime?.integrations?.[service.integrationKey ?? service.id];
                      const style = result ? testStyle(result) : null;
                      const ResultIcon = style?.icon;
                      return (
                        <div key={service.id} className="space-y-1.5">
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2 text-xs">
                              <span className="font-semibold text-slate-200">{service.label}</span>
                              {configured !== undefined && (
                                <span className={`text-[10px] px-1.5 py-0.5 rounded border ${configured ? "bg-blue-500/10 text-blue-300 border-blue-500/20" : "bg-slate-800 text-slate-500 border-slate-700"}`}>
                                  {configured ? "Configured" : "Not configured"}
                                </span>
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => void runTest(category, service.id, service.label, service.overrides)}
                              disabled={!canEdit || testing !== null}
                              title={canEdit ? `Run a read-only authentication check against ${service.label}` : "Administrators only"}
                              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 text-xs font-semibold disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                            >
                              <Activity className={`h-3.5 w-3.5 text-blue-400 ${testing === service.id ? "animate-spin" : ""}`} aria-hidden="true" />
                              <span>{testing === service.id ? "Testing..." : "Test"}</span>
                            </button>
                          </div>
                          {result && style && ResultIcon && (
                            <div role="status" className={`p-2.5 rounded-lg border text-xs ${style.className}`}>
                              <div className="flex items-start gap-2">
                                <ResultIcon className="h-4 w-4 flex-shrink-0 mt-0.5" aria-hidden="true" />
                                <div className="space-y-0.5">
                                  <div className="font-bold flex items-center gap-2">
                                    <span>{result.status}</span>
                                    {result.health && result.health !== result.status && <span className="font-normal opacity-80">&middot; {result.health}</span>}
                                    {typeof result.latency_ms === "number" && result.latency_ms > 0 && <span className="font-mono text-[10px] opacity-75">({result.latency_ms}ms)</span>}
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
              </section>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
