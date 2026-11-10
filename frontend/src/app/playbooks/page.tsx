"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  ScrollText,
  Plus,
  Settings,
  Trash2,
  Cpu,
  Layers,
  CheckCircle2,
  X,
  Save,
  Code,
  AlertCircle,
  AlertTriangle,
  Copy,
  Check,
  RefreshCw,
  Zap,
  Lock
} from "lucide-react";
import { ExecutionMode, Playbook } from "@/lib/types";
import { api } from "@/lib/api";
import { isSecEngOrAdmin } from "@/lib/roles";
import { ActionCatalog, ActionSpec, FALLBACK_ACTIONS, PSEUDO_STEP_LABELS, formatParams, parseParams } from "@/lib/actions";
import { useAuth } from "@/components/AuthGate";

// Names accepted by the runner for older playbooks (backend ACTION_ALIASES).
const ACTION_ALIASES: Record<string, string> = {
  create_jira_ticket: "create_ticket",
  terminate_session: "revoke_user_sessions",
  disable_user_account: "disable_account",
  notify: "send_notification",
};

const THREAT_OPTIONS = [
  "Ransomware",
  "Phishing",
  "Brute Force",
  "Web Attack",
  "Lateral Movement",
  "Credential Access",
  "Data Exfiltration",
  "Malware",
  "Custom",
];

const PICERL_PHASES = ["Identification", "Containment", "Eradication", "Recovery"];

interface BuilderStep {
  id: number;
  action: string;
  params: string;
}

function parseLogic(pb: Pick<Playbook, "workflow_logic">): Record<string, any> {
  const logic = pb.workflow_logic;
  if (typeof logic === "string") {
    try {
      const parsed = JSON.parse(logic);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }
  return logic && typeof logic === "object" ? logic : {};
}

function stepsOf(logic: Record<string, any>): Array<Record<string, any>> {
  return Array.isArray(logic.steps) ? logic.steps.filter((s: unknown) => s && typeof s === "object") : [];
}

export default function PlaybooksPage() {
  const { user } = useAuth();
  const canEditPlaybooks = isSecEngOrAdmin(user);

  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [modeFilter, setModeFilter] = useState<string>("ALL");
  const [busyIds, setBusyIds] = useState<Record<number, boolean>>({});

  const [catalog, setCatalog] = useState<ActionCatalog>(FALLBACK_ACTIONS);
  const [catalogLive, setCatalogLive] = useState<boolean>(false);
  const [templates, setTemplates] = useState<Awaited<ReturnType<typeof api.getPlaybookTemplates>>>([]);

  // Editor modal
  const [editing, setEditing] = useState<Playbook | null>(null);
  const [editName, setEditName] = useState<string>("");
  const [editThreat, setEditThreat] = useState<string>("");
  const [editMode, setEditMode] = useState<ExecutionMode>("HITL");
  const [editJson, setEditJson] = useState<string>("");
  const [editError, setEditError] = useState<string | null>(null);
  const [editSaving, setEditSaving] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  // Create modal
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [createName, setCreateName] = useState<string>("");
  const [createThreat, setCreateThreat] = useState<string>("Ransomware");
  const [createCustomThreat, setCreateCustomThreat] = useState<string>("");
  const [createMode, setCreateMode] = useState<ExecutionMode>("HITL");
  const [createMitreId, setCreateMitreId] = useState<string>("");
  const [createPicerl, setCreatePicerl] = useState<string>("Containment");
  const [createKeywords, setCreateKeywords] = useState<string>("");
  const [createSteps, setCreateSteps] = useState<BuilderStep[]>([
    { id: 1, action: "isolate_endpoint", params: "" },
    { id: 2, action: "generate_report", params: "" },
  ]);
  const [createTab, setCreateTab] = useState<"builder" | "json">("builder");
  const [createJson, setCreateJson] = useState<string>("");
  const [createLoading, setCreateLoading] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const actionsByName = useMemo(() => {
    const map: Record<string, ActionSpec> = {};
    catalog.actions.forEach((a) => (map[a.name] = a));
    return map;
  }, [catalog]);

  const knownStep = useCallback(
    (name: string) => Boolean(actionsByName[ACTION_ALIASES[name] || name] || catalog.pseudo_steps[name]),
    [actionsByName, catalog]
  );

  const loadPlaybooks = useCallback(async () => {
    setLoading(true);
    try {
      const remote = await api.getPlaybooks();
      setPlaybooks(remote || []);
      setLoadError(null);
    } catch (err: any) {
      setLoadError(err.message || "Could not load playbooks.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPlaybooks();
    api.getPlaybookActions()
      .then((c) => {
        if (c && Array.isArray(c.actions)) {
          setCatalog({ actions: c.actions, pseudo_steps: c.pseudo_steps || {} });
          setCatalogLive(true);
        }
      })
      .catch(() => setCatalogLive(false));
    api.getPlaybookTemplates().then((t) => setTemplates(Array.isArray(t) ? t : [])).catch(() => setTemplates([]));
  }, [loadPlaybooks]);

  const showNotice = (text: string) => {
    setNotice(text);
    setTimeout(() => setNotice(null), 4000);
  };

  const setBusy = (id: number, busy: boolean) => setBusyIds((prev) => ({ ...prev, [id]: busy }));

  // --- Toggle / delete -----------------------------------------------------
  const handleToggle = async (e: React.MouseEvent, pb: Playbook) => {
    e.stopPropagation();
    if (!canEditPlaybooks || busyIds[pb.playbook_id]) return;
    setPageError(null);
    setBusy(pb.playbook_id, true);
    try {
      const res = await api.togglePlaybook(pb.playbook_id);
      const nextActive = typeof res?.is_active === "boolean" ? res.is_active : !pb.is_active;
      setPlaybooks((prev) => prev.map((p) => (p.playbook_id === pb.playbook_id ? { ...p, is_active: nextActive } : p)));
      showNotice(`Playbook "${pb.name}" ${nextActive ? "enabled" : "disabled"}.`);
    } catch (err: any) {
      setPageError(`Could not toggle "${pb.name}": ${err.message || "request failed"}`);
    } finally {
      setBusy(pb.playbook_id, false);
    }
  };

  const handleDelete = async (e: React.MouseEvent, pb: Playbook) => {
    e.stopPropagation();
    if (!canEditPlaybooks) return;
    if (!confirm(`Delete playbook "${pb.name}"? Past executions keep their records.`)) return;
    setPageError(null);
    setBusy(pb.playbook_id, true);
    try {
      await api.deletePlaybook(pb.playbook_id);
      setPlaybooks((prev) => prev.filter((p) => p.playbook_id !== pb.playbook_id));
      showNotice(`Playbook "${pb.name}" deleted.`);
    } catch (err: any) {
      setPageError(`Could not delete "${pb.name}": ${err.message || "request failed"}`);
    } finally {
      setBusy(pb.playbook_id, false);
    }
  };

  // --- Editor ----------------------------------------------------------------
  const openEditor = (pb: Playbook) => {
    setEditing(pb);
    setEditName(pb.name);
    setEditThreat(pb.target_threat);
    setEditMode(pb.execution_mode);
    setEditJson(JSON.stringify(parseLogic(pb), null, 2));
    setEditError(null);
    setCopied(false);
  };

  const validateWorkflow = (text: string): { logic: Record<string, any> | null; error: string | null; warnings: string[] } => {
    let logic: unknown;
    try {
      logic = JSON.parse(text);
    } catch (e: any) {
      return { logic: null, error: `Invalid JSON: ${e.message}`, warnings: [] };
    }
    if (!logic || typeof logic !== "object" || Array.isArray(logic)) {
      return { logic: null, error: "workflow_logic must be a JSON object.", warnings: [] };
    }
    const steps = (logic as Record<string, any>).steps;
    if (steps !== undefined && !Array.isArray(steps)) {
      return { logic: null, error: "\"steps\" must be an array.", warnings: [] };
    }
    const warnings: string[] = [];
    (Array.isArray(steps) ? steps : []).forEach((s: any, i: number) => {
      if (!s || typeof s !== "object" || typeof s.action !== "string") {
        warnings.push(`Step ${i + 1} has no "action".`);
      } else if (!knownStep(s.action)) {
        warnings.push(`Step ${i + 1}: "${s.action}" is not a known action; the runner will skip it.`);
      } else if (s.params !== undefined && (typeof s.params !== "object" || Array.isArray(s.params))) {
        warnings.push(`Step ${i + 1}: "params" must be an object.`);
      }
    });
    return { logic: logic as Record<string, any>, error: null, warnings };
  };

  const editValidation = editing ? validateWorkflow(editJson) : null;

  const handleSaveEditor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editing || !canEditPlaybooks) return;
    const { logic, error } = validateWorkflow(editJson);
    if (error || !logic) {
      setEditError(error);
      return;
    }
    setEditSaving(true);
    setEditError(null);
    try {
      const updated = await api.updatePlaybook(editing.playbook_id, {
        name: editName.trim() || editing.name,
        target_threat: editThreat.trim() || editing.target_threat,
        execution_mode: editMode,
        workflow_logic: logic,
      });
      setPlaybooks((prev) =>
        prev.map((p) =>
          p.playbook_id === editing.playbook_id
            ? { ...p, ...(updated || {}), workflow_logic: updated?.workflow_logic ?? logic }
            : p
        )
      );
      setEditing(null);
      showNotice(`Playbook "${editName.trim() || editing.name}" saved.`);
    } catch (err: any) {
      setEditError(`Save failed: ${err.message || "request failed"}`);
    } finally {
      setEditSaving(false);
    }
  };

  // --- Builder -----------------------------------------------------------------
  const builderLogic = (): { logic: Record<string, any> | null; error: string | null } => {
    const steps: Array<Record<string, unknown>> = [];
    for (let i = 0; i < createSteps.length; i++) {
      const st = createSteps[i];
      const { params, error } = parseParams(st.params);
      if (error) return { logic: null, error: `Step ${i + 1}: ${error}` };
      const spec = actionsByName[st.action];
      steps.push({
        order: i + 1,
        action: st.action,
        ...(spec ? { connector: spec.connector } : {}),
        ...(Object.keys(params).length ? { params } : {}),
      });
    }
    const keywords = createKeywords
      .split(",")
      .map((k) => k.trim())
      .filter(Boolean);
    return {
      logic: {
        ...(createMitreId.trim() ? { mitre_id: createMitreId.trim().toUpperCase() } : {}),
        picerl_phase: createPicerl,
        ...(keywords.length ? { keywords } : {}),
        steps,
      },
      error: null,
    };
  };

  const openCreate = () => {
    setCreateError(null);
    setCreateTab("builder");
    setIsCreateOpen(true);
  };

  const applyTemplate = (index: number) => {
    const t = templates[index];
    if (!t) return;
    const logic = parseLogic(t);
    setCreateName(`${t.name} (copy)`);
    if (THREAT_OPTIONS.includes(t.target_threat)) {
      setCreateThreat(t.target_threat);
      setCreateCustomThreat("");
    } else {
      setCreateThreat("Custom");
      setCreateCustomThreat(t.target_threat);
    }
    setCreateMode(t.execution_mode);
    setCreateMitreId(logic.mitre_id || "");
    setCreatePicerl(PICERL_PHASES.includes(logic.picerl_phase) ? logic.picerl_phase : "Containment");
    setCreateKeywords(Array.isArray(logic.keywords) ? logic.keywords.join(", ") : "");
    setCreateSteps(
      stepsOf(logic).map((s, i) => ({ id: i + 1, action: String(s.action || ""), params: formatParams(s.params) }))
    );
    setCreateTab("builder");
  };

  const switchToJson = () => {
    const { logic, error } = builderLogic();
    if (error || !logic) {
      setCreateError(error);
      return;
    }
    setCreateError(null);
    setCreateJson(JSON.stringify(logic, null, 2));
    setCreateTab("json");
  };

  const handleCreatePlaybook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createName.trim()) {
      setCreateError("Please give the playbook a name.");
      return;
    }
    let logic: Record<string, any> | null;
    if (createTab === "json") {
      const v = validateWorkflow(createJson);
      if (v.error || !v.logic) {
        setCreateError(v.error);
        return;
      }
      logic = v.logic;
    } else {
      const b = builderLogic();
      if (b.error || !b.logic) {
        setCreateError(b.error);
        return;
      }
      logic = b.logic;
    }

    const finalThreat = createThreat === "Custom" ? createCustomThreat.trim() : createThreat;
    if (!finalThreat) {
      setCreateError("Please name the target threat.");
      return;
    }

    setCreateLoading(true);
    setCreateError(null);
    try {
      const created = await api.createPlaybook({
        name: createName.trim(),
        target_threat: finalThreat,
        execution_mode: createMode,
        workflow_logic: logic,
        is_active: true,
      });
      setPlaybooks((prev) => [created, ...prev]);
      setIsCreateOpen(false);
      setCreateName("");
      setCreateCustomThreat("");
      showNotice(`Playbook "${created.name}" created and active.`);
    } catch (err: any) {
      setCreateError(err.message || "Failed to create playbook.");
    } finally {
      setCreateLoading(false);
    }
  };

  const filteredPlaybooks = playbooks.filter((p) => modeFilter === "ALL" || (p.execution_mode || "").toUpperCase() === modeFilter);

  const actionOptions = (
    <>
      <optgroup label="Response actions">
        {catalog.actions.map((a) => (
          <option key={a.name} value={a.name}>
            {a.name} ({a.connector}, {a.impact} impact)
          </option>
        ))}
      </optgroup>
      <optgroup label="Runner steps">
        {Object.entries(catalog.pseudo_steps).map(([name, kind]) => (
          <option key={name} value={name}>
            {name} ({kind})
          </option>
        ))}
      </optgroup>
    </>
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2.5">
            <h1 className="text-2xl font-black text-white tracking-tight">Playbook Automation Catalog</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-bold">
              {playbooks.length} Configured
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            The runner matches an alert to the best active playbook (MITRE technique and threat keywords) and executes
            its steps through the policy engine. HOTL playbooks act automatically only with real evidence; HITL playbooks wait for an analyst.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {canEditPlaybooks ? (
            <button
              onClick={openCreate}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-blue-600/25 transition flex-shrink-0"
            >
              <Plus className="h-4 w-4" />
              <span>Create Playbook</span>
            </button>
          ) : (
            <div className="flex items-center space-x-1.5 px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-medium text-slate-400 flex-shrink-0">
              <Lock className="h-3.5 w-3.5 text-amber-400" />
              <span>Read-only (Security Engineers & Admins can edit)</span>
            </div>
          )}

          <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 p-1.5 rounded-xl text-xs">
            {["ALL", "HOTL", "HITL"].map((m) => (
              <button
                key={m}
                onClick={() => setModeFilter(m)}
                className={`px-3 py-1.5 rounded-lg font-bold text-[11px] transition ${
                  modeFilter === m ? "bg-blue-600 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {m === "ALL" ? "All" : m}
              </button>
            ))}
          </div>
        </div>
      </div>

      {notice && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center space-x-2">
          <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
          <span>{notice}</span>
        </div>
      )}
      {(pageError || loadError) && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center justify-between">
          <span className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            {pageError || loadError}
          </span>
          {loadError && (
            <button onClick={loadPlaybooks} className="underline font-semibold">Retry</button>
          )}
        </div>
      )}

      {loading ? (
        <div className="flex flex-col items-center justify-center py-20 space-y-3">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
          <p className="text-sm text-slate-400">Loading playbooks...</p>
        </div>
      ) : filteredPlaybooks.length === 0 && !loadError ? (
        <div className="py-16 text-center space-y-2 bg-slate-900/60 border border-slate-800 rounded-xl">
          <ScrollText className="h-8 w-8 mx-auto text-slate-500" />
          <p className="text-sm font-semibold text-slate-300">
            {playbooks.length === 0 ? "No playbooks are configured." : "No playbooks match this filter."}
          </p>
          {playbooks.length === 0 && (
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Create one from a template, or (admin, simulation mode) use Generate Demo Data on the dashboard to load the lab catalog.
              Without a matching playbook every alert goes to analyst review.
            </p>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredPlaybooks.map((pb) => {
            const isHOTL = (pb.execution_mode || "").toUpperCase() === "HOTL";
            const logic = parseLogic(pb);
            const steps = stepsOf(logic);
            const unknownSteps = steps.filter((s) => typeof s.action !== "string" || !knownStep(s.action));
            const busy = Boolean(busyIds[pb.playbook_id]);

            return (
              <div
                key={pb.playbook_id}
                onClick={() => openEditor(pb)}
                className="flex flex-col overflow-hidden bg-slate-900 border border-slate-800 rounded-xl shadow-lg hover:border-slate-700 transition cursor-pointer group relative"
              >
                <div className="p-5 flex-1 space-y-3 overflow-hidden">
                  <div className="flex items-start justify-between gap-2 overflow-hidden">
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5 mb-1">
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400 flex-shrink-0">
                          ID #{pb.playbook_id}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 truncate max-w-[140px]">
                          {pb.target_threat}
                        </span>
                      </div>
                      <h3 className="font-bold text-sm text-white group-hover:text-blue-400 transition leading-snug truncate">
                        {pb.name}
                      </h3>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border flex-shrink-0 ${
                        isHOTL ? "bg-blue-500/10 text-blue-400 border-blue-500/30" : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                      }`}
                    >
                      {pb.execution_mode}
                    </span>
                  </div>

                  <div className="pt-2 border-t border-slate-800/80 space-y-2 text-xs">
                    <div className="flex items-center justify-between text-slate-400">
                      <span>SANS IR Phase:</span>
                      <span className="font-semibold text-emerald-400">{logic.picerl_phase || "—"}</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-400">
                      <span>MITRE Technique:</span>
                      <span className="font-mono text-purple-400 font-semibold">{logic.mitre_id || "—"}</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Steps:</span>
                      <span className="font-mono text-slate-200">{steps.length}</span>
                    </div>
                    {steps.length > 0 && (
                      <div className="text-[11px] font-mono text-slate-400 truncate" title={steps.map((s) => s.action).join(" → ")}>
                        {steps.map((s) => s.action).join(" → ")}
                      </div>
                    )}
                    {unknownSteps.length > 0 && (
                      <div className="text-[11px] text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        {unknownSteps.length} unknown step{unknownSteps.length === 1 ? "" : "s"} (skipped by the runner)
                      </div>
                    )}
                  </div>
                </div>

                <div className="px-4 py-3 bg-slate-950/80 border-t border-slate-800 flex items-center justify-between gap-2 overflow-hidden flex-shrink-0">
                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <span className={`h-2 w-2 rounded-full ${pb.is_active ? "bg-emerald-400" : "bg-slate-600"}`} />
                    <span className="text-[11px] font-medium text-slate-400">{pb.is_active ? "Active" : "Disabled"}</span>
                  </div>

                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={pb.is_active}
                      disabled={!canEditPlaybooks || busy}
                      onClick={(e) => handleToggle(e, pb)}
                      className={`relative inline-flex h-5 w-10 flex-shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none ${
                        !canEditPlaybooks || busy ? "cursor-not-allowed opacity-50" : "cursor-pointer"
                      } ${pb.is_active ? "bg-emerald-500" : "bg-slate-700"}`}
                      title={!canEditPlaybooks ? "Only Security Engineers and Admins can toggle playbooks." : pb.is_active ? "Disable playbook" : "Enable playbook"}
                    >
                      <span
                        aria-hidden="true"
                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-md transition duration-200 ${
                          pb.is_active ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>

                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        openEditor(pb);
                      }}
                      className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 transition flex-shrink-0"
                      title={canEditPlaybooks ? "Edit playbook" : "Inspect playbook (read-only)"}
                    >
                      <Settings className="h-3.5 w-3.5 text-blue-400" />
                    </button>

                    {canEditPlaybooks && (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={(e) => handleDelete(e, pb)}
                        className="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-600 text-rose-400 hover:text-white border border-rose-500/20 transition flex-shrink-0 disabled:opacity-50"
                        title="Delete playbook"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* EDITOR MODAL */}
      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div
            className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[92vh] flex flex-col shadow-2xl shadow-black overflow-hidden relative"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-5 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="h-9 w-9 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
                  <Code className="h-4 w-4 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white tracking-wide">
                    {canEditPlaybooks ? "Edit Playbook" : "Inspect Playbook"}: <span className="text-blue-400">{editing.name}</span>
                  </h2>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    ID #{editing.playbook_id} | workflow_logic is the JSON the runner executes
                  </p>
                </div>
              </div>
              <button
                onClick={() => setEditing(null)}
                className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition border border-slate-700/60"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleSaveEditor} className="flex-1 overflow-y-auto p-6 space-y-4 flex flex-col">
              {!canEditPlaybooks && (
                <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center space-x-2.5">
                  <Lock className="h-4 w-4 text-amber-400 flex-shrink-0" />
                  <span>Read-only: your role ({user?.role || "unknown"}) cannot modify playbooks.</span>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="space-y-1 sm:col-span-1">
                  <label className="text-[11px] font-semibold text-slate-300">Name</label>
                  <input
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    readOnly={!canEditPlaybooks}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-semibold text-slate-300">Target threat</label>
                  <input
                    value={editThreat}
                    onChange={(e) => setEditThreat(e.target.value)}
                    readOnly={!canEditPlaybooks}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-semibold text-slate-300">Execution mode</label>
                  <select
                    value={editMode}
                    onChange={(e) => setEditMode(e.target.value as ExecutionMode)}
                    disabled={!canEditPlaybooks}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                  >
                    <option value="HITL">HITL (analyst approval)</option>
                    <option value="HOTL">HOTL (automatic with evidence)</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-semibold text-slate-300">workflow_logic (JSON)</span>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(editJson);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
                >
                  {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  <span>{copied ? "Copied" : "Copy JSON"}</span>
                </button>
              </div>

              <textarea
                value={editJson}
                onChange={(e) => setEditJson(e.target.value)}
                readOnly={!canEditPlaybooks}
                className="w-full min-h-[320px] bg-slate-950 font-mono text-xs text-slate-200 border border-slate-800 rounded-xl p-4 focus:outline-none focus:border-blue-500 leading-relaxed resize-y"
                spellCheck={false}
              />

              {editValidation?.error && (
                <div className="text-[11px] text-rose-400 flex items-center gap-1.5">
                  <AlertCircle className="h-3.5 w-3.5" />
                  {editValidation.error}
                </div>
              )}
              {editValidation?.warnings.map((w, i) => (
                <div key={i} className="text-[11px] text-amber-400 flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  {w}
                </div>
              ))}
              {editError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">{editError}</div>
              )}

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">
                  Steps: {"{order, action, params}"}. Targets come from the alert&apos;s own entities; unsupported params are ignored.
                </span>
                <div className="flex items-center space-x-3">
                  <button
                    type="button"
                    onClick={() => setEditing(null)}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
                  >
                    {canEditPlaybooks ? "Cancel" : "Close"}
                  </button>
                  {canEditPlaybooks && (
                    <button
                      type="submit"
                      disabled={editSaving || Boolean(editValidation?.error)}
                      className="flex items-center space-x-1.5 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition disabled:opacity-50"
                    >
                      <Save className="h-3.5 w-3.5" />
                      <span>{editSaving ? "Saving..." : "Save Changes"}</span>
                    </button>
                  )}
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CREATE MODAL */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center space-x-3">
                <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
                  <Plus className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white tracking-wide">Create Playbook</h2>
                  <p className="text-xs text-slate-400">
                    Matching uses the MITRE technique, target threat and keywords. Steps run through the policy engine.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsCreateOpen(false)}
                className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition border border-slate-700/60"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {createError && (
              <div className="m-5 mb-0 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center space-x-2">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{createError}</span>
              </div>
            )}

            <div className="px-6 pt-4 flex items-center justify-between border-b border-slate-800 bg-slate-950/30">
              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => setCreateTab("builder")}
                  className={`flex items-center space-x-2 px-4 py-2 text-xs font-bold border-b-2 transition ${
                    createTab === "builder" ? "border-blue-500 text-blue-400 bg-blue-500/10 rounded-t-lg" : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Layers className="h-3.5 w-3.5" />
                  <span>Builder</span>
                </button>
                <button
                  type="button"
                  onClick={switchToJson}
                  className={`flex items-center space-x-2 px-4 py-2 text-xs font-bold border-b-2 transition ${
                    createTab === "json" ? "border-blue-500 text-blue-400 bg-blue-500/10 rounded-t-lg" : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Code className="h-3.5 w-3.5" />
                  <span>JSON</span>
                </button>
              </div>
              {templates.length > 0 && (
                <select
                  defaultValue=""
                  onChange={(e) => {
                    if (e.target.value !== "") applyTemplate(Number(e.target.value));
                    e.target.value = "";
                  }}
                  className="mb-2 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300"
                >
                  <option value="">Start from template…</option>
                  {templates.map((t, i) => (
                    <option key={`${t.name}-${i}`} value={i}>{t.name}</option>
                  ))}
                </select>
              )}
            </div>

            <form onSubmit={handleCreatePlaybook} className="flex-1 overflow-y-auto p-6 space-y-5">
              {/* Identity (shared by both tabs) */}
              <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Cpu className="h-3.5 w-3.5 text-blue-400" />
                  1. Identity & Matching
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                  <div className="space-y-1 sm:col-span-2">
                    <label className="text-xs font-semibold text-slate-300">Playbook name *</label>
                    <input
                      type="text"
                      required
                      value={createName}
                      onChange={(e) => setCreateName(e.target.value)}
                      placeholder="e.g. Web Shell Containment"
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-slate-300">Target threat</label>
                    <select
                      value={createThreat}
                      onChange={(e) => setCreateThreat(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                    >
                      {THREAT_OPTIONS.map((t) => (
                        <option key={t} value={t}>{t === "Custom" ? "Custom threat name" : t}</option>
                      ))}
                    </select>
                  </div>
                  {createThreat === "Custom" && (
                    <div className="space-y-1">
                      <label className="text-xs font-semibold text-slate-300">Custom threat name *</label>
                      <input
                        type="text"
                        value={createCustomThreat}
                        onChange={(e) => setCreateCustomThreat(e.target.value)}
                        placeholder="e.g. Cryptojacking"
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  )}
                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-slate-300">Execution mode</label>
                    <select
                      value={createMode}
                      onChange={(e) => setCreateMode(e.target.value as ExecutionMode)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                    >
                      <option value="HITL">HITL (analyst approval required)</option>
                      <option value="HOTL">HOTL (automatic only with real evidence)</option>
                    </select>
                  </div>
                  {createTab === "builder" && (
                    <>
                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">SANS PICERL phase</label>
                        <select
                          value={createPicerl}
                          onChange={(e) => setCreatePicerl(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                        >
                          {PICERL_PHASES.map((p) => <option key={p} value={p}>{p}</option>)}
                        </select>
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">MITRE ATT&CK technique</label>
                        <input
                          type="text"
                          value={createMitreId}
                          onChange={(e) => setCreateMitreId(e.target.value)}
                          placeholder="e.g. T1190"
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono"
                        />
                      </div>
                      <div className="space-y-1 sm:col-span-2">
                        <label className="text-xs font-semibold text-slate-300">Match keywords (comma separated)</label>
                        <input
                          type="text"
                          value={createKeywords}
                          onChange={(e) => setCreateKeywords(e.target.value)}
                          placeholder="e.g. web shell, cmd.exe spawned by w3wp"
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                        />
                      </div>
                    </>
                  )}
                </div>
              </div>

              {createTab === "builder" ? (
                <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Zap className="h-3.5 w-3.5 text-amber-400" />
                      2. Steps ({createSteps.length})
                    </h3>
                    <button
                      type="button"
                      onClick={() =>
                        setCreateSteps((prev) => [...prev, { id: (prev[prev.length - 1]?.id || 0) + 1, action: "create_ticket", params: "" }])
                      }
                      className="flex items-center space-x-1 px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-xs font-semibold transition"
                    >
                      <Plus className="h-3 w-3" />
                      <span>Add Step</span>
                    </button>
                  </div>
                  {!catalogLive && (
                    <p className="text-[11px] text-amber-400">Action catalog could not be loaded from the server; showing the built-in list.</p>
                  )}

                  <div className="space-y-2.5">
                    {createSteps.map((step, idx) => {
                      const spec = actionsByName[step.action];
                      const pseudo = catalog.pseudo_steps[step.action];
                      const paramNames = spec?.params ? Object.keys(spec.params) : [];
                      const parsed = parseParams(step.params);
                      return (
                        <div key={step.id} className="p-3 bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2">
                            <span className="h-6 w-6 rounded-lg bg-blue-600/20 text-blue-400 text-xs font-bold flex items-center justify-center font-mono flex-shrink-0">
                              {idx + 1}
                            </span>
                            <select
                              value={step.action}
                              onChange={(e) =>
                                setCreateSteps((prev) => prev.map((s) => (s.id === step.id ? { ...s, action: e.target.value, params: "" } : s)))
                              }
                              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono"
                            >
                              {!knownStep(step.action) && <option value={step.action}>{step.action} (unknown)</option>}
                              {actionOptions}
                            </select>
                            <input
                              type="text"
                              value={step.params}
                              disabled={Boolean(pseudo) || (spec && paramNames.length === 0)}
                              onChange={(e) =>
                                setCreateSteps((prev) => prev.map((s) => (s.id === step.id ? { ...s, params: e.target.value } : s)))
                              }
                              placeholder={pseudo || (spec && paramNames.length === 0) ? "no params" : `params, e.g. ${paramNames[0] || "key"}: value`}
                              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono placeholder-slate-600 disabled:opacity-50"
                            />
                            {createSteps.length > 1 && (
                              <button
                                type="button"
                                onClick={() => setCreateSteps((prev) => prev.filter((s) => s.id !== step.id))}
                                className="p-1.5 text-slate-500 hover:text-rose-400 rounded-lg hover:bg-slate-800 transition"
                                title="Remove step"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </button>
                            )}
                          </div>
                          <div className="text-[10px] text-slate-500 pl-8">
                            {pseudo
                              ? PSEUDO_STEP_LABELS[pseudo] || pseudo
                              : spec
                              ? `${spec.description || ""} Target: ${spec.target_type === "none" ? "none" : `the alert's ${spec.target_type}`} · impact ${spec.impact}${paramNames.length ? ` · params: ${paramNames.join(", ")}` : ""}`
                              : "Unknown action: the runner will skip it."}
                            {parsed.error && <span className="text-rose-400"> · {parsed.error}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-xs text-slate-400">
                    workflow_logic JSON (edit freely; this is exactly what is saved):
                  </div>
                  <textarea
                    rows={16}
                    value={createJson}
                    onChange={(e) => setCreateJson(e.target.value)}
                    className="w-full bg-slate-950 font-mono text-xs text-emerald-400 border border-slate-800 rounded-xl p-4 focus:outline-none focus:border-blue-500 leading-relaxed"
                    spellCheck={false}
                  />
                  {(() => {
                    const v = validateWorkflow(createJson);
                    return (
                      <>
                        {v.error && <div className="text-[11px] text-rose-400">{v.error}</div>}
                        {v.warnings.map((w, i) => <div key={i} className="text-[11px] text-amber-400">{w}</div>)}
                      </>
                    );
                  })()}
                </div>
              )}

              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">New playbooks are saved as active.</span>
                <div className="flex items-center space-x-3">
                  <button
                    type="button"
                    onClick={() => setIsCreateOpen(false)}
                    className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={createLoading}
                    className="flex items-center space-x-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition disabled:opacity-50"
                  >
                    {createLoading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                    <span>{createLoading ? "Creating..." : "Create Playbook"}</span>
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
