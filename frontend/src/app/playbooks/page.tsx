"use client";

import React, { useState, useEffect } from "react";
import { 
  ScrollText, 
  Plus, 
  Power, 
  Settings, 
  Trash2, 
  Cpu, 
  Layers, 
  CheckCircle2, 
  X, 
  Save, 
  Code, 
  FileCode, 
  AlertCircle,
  Copy,
  Check,
  RefreshCw,
  Zap,
  Lock,
  ShieldAlert
} from "lucide-react";
import { Playbook, ExecutionMode, User } from "@/lib/types";
import { api } from "@/lib/api";
import { getStoredUser, subscribeToAuth } from "@/lib/auth";

// 12 Pre-configured SANS / MITRE Playbook definitions
const INITIAL_PLAYBOOKS: Playbook[] = [
  {
    playbook_id: 1,
    name: "Ransomware Outbreak Containment",
    target_threat: "Ransomware",
    execution_mode: "HOTL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1486",
      picerl_phase: "Containment",
      language: "yaml",
      code: `name: Ransomware Outbreak Containment
mitre_technique: T1486
execution_mode: HOTL
steps:
  - step: 1
    action: isolate_endpoint
    connector: edr
    params: { kill_network: true, retain_management: true }
  - step: 2
    action: terminate_process
    connector: edr
    params: { target_tree: "encryptor.exe" }
  - step: 3
    action: block_ip
    connector: firewall
    params: { direction: both, duration_hours: 48 }
  - step: 4
    action: revoke_user_sessions
    connector: iam
    params: { revoke_tokens: true }
  - step: 5
    action: generate_pdf_report
    connector: reporter`
    }
  },
  {
    playbook_id: 2,
    name: "SSH & RDP Brute Force Mitigation",
    target_threat: "Brute Force",
    execution_mode: "HOTL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1110",
      picerl_phase: "Identification & Containment",
      language: "yaml",
      code: `name: SSH & RDP Brute Force Mitigation
mitre_technique: T1110
execution_mode: HOTL
steps:
  - step: 1
    action: query_abuseipdb
    connector: tip
    threshold: 50
  - step: 2
    action: block_ip
    connector: firewall
    params: { rule: "EDGE_DROP_ATTACKER_IP" }
  - step: 3
    action: apply_rate_limit
    connector: firewall
    rate: "5/min"
  - step: 4
    action: create_jira_ticket
    connector: itsm
    priority: "Medium"`
    }
  },
  {
    playbook_id: 3,
    name: "Spearphishing Email & Credential Harvesting",
    target_threat: "Phishing",
    execution_mode: "HITL",
    is_active: false,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1566",
      picerl_phase: "Identification",
      language: "yaml",
      code: `name: Spearphishing Email & Credential Harvesting
mitre_technique: T1566
execution_mode: HITL
steps:
  - step: 1
    action: query_virustotal_url
    connector: tip
  - step: 2
    action: await_analyst_approval
    gate: "SOC Analyst L2 Review"
  - step: 3
    action: purge_email_inbox
    connector: mail_gateway
  - step: 4
    action: revoke_user_sessions
    connector: iam`
    }
  },
  {
    playbook_id: 4,
    name: "Privilege Escalation via Token Impersonation",
    target_threat: "Privilege Escalation",
    execution_mode: "HITL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1068",
      picerl_phase: "Containment",
      language: "yaml",
      code: `name: Privilege Escalation via Token Impersonation
mitre_technique: T1068
execution_mode: HITL
steps:
  - step: 1
    action: terminate_process
    connector: edr
  - step: 2
    action: isolate_endpoint
    connector: edr
  - step: 3
    action: await_analyst_approval
    gate: "Incident Commander Sign-off"`
    }
  },
  {
    playbook_id: 5,
    name: "Web Shell Execution & Backdoor Isolation",
    target_threat: "WebShell",
    execution_mode: "HOTL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1505.003",
      picerl_phase: "Eradication",
      language: "yaml",
      code: `name: Web Shell Execution & Backdoor Isolation
mitre_technique: T1505.003
execution_mode: HOTL
steps:
  - step: 1
    action: quarantine_file
    connector: edr
  - step: 2
    action: block_ip
    connector: firewall
  - step: 3
    action: isolate_endpoint
    connector: edr`
    }
  },
  {
    playbook_id: 6,
    name: "Data Exfiltration over Covert C2 Protocol",
    target_threat: "Data Exfiltration",
    execution_mode: "HOTL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1048",
      picerl_phase: "Containment",
      language: "yaml",
      code: `name: Data Exfiltration over Covert C2 Protocol
mitre_technique: T1048
execution_mode: HOTL
steps:
  - step: 1
    action: block_ip
    connector: firewall
  - step: 2
    action: apply_rate_limit
    connector: firewall
  - step: 3
    action: isolate_endpoint
    connector: edr`
    }
  },
  {
    playbook_id: 7,
    name: "Lateral Movement via SMB & PsExec",
    target_threat: "Lateral Movement",
    execution_mode: "HITL",
    is_active: false,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1550",
      picerl_phase: "Containment",
      language: "yaml",
      code: `name: Lateral Movement via SMB & PsExec
mitre_technique: T1550
execution_mode: HITL
steps:
  - step: 1
    action: isolate_endpoint
    connector: edr
  - step: 2
    action: await_analyst_approval
    gate: "Tier 2 Lead Sign-off"`
    }
  },
  {
    playbook_id: 8,
    name: "DDoS Flood Perimeter Mitigation",
    target_threat: "DDoS Mitigation",
    execution_mode: "HOTL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1498",
      picerl_phase: "Containment",
      language: "yaml",
      code: `name: DDoS Flood Perimeter Mitigation
mitre_technique: T1498
execution_mode: HOTL
steps:
  - step: 1
    action: apply_rate_limit
    connector: firewall
    rate: "10/sec"
  - step: 2
    action: block_ip
    connector: firewall`
    }
  },
  {
    playbook_id: 9,
    name: "Credential Dumping via LSASS Injection",
    target_threat: "Credential Dumping",
    execution_mode: "HOTL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1003",
      picerl_phase: "Containment",
      language: "yaml",
      code: `name: Credential Dumping via LSASS Injection
mitre_technique: T1003
execution_mode: HOTL
steps:
  - step: 1
    action: terminate_process
    connector: edr
  - step: 2
    action: isolate_endpoint
    connector: edr
  - step: 3
    action: force_password_reset
    connector: iam`
    }
  },
  {
    playbook_id: 10,
    name: "Database SQL Injection & Unauthorized Export",
    target_threat: "Data Tampering",
    execution_mode: "HITL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1190",
      picerl_phase: "Identification",
      language: "yaml",
      code: `name: Database SQL Injection & Unauthorized Export
mitre_technique: T1190
execution_mode: HITL
steps:
  - step: 1
    action: block_ip
    connector: firewall
  - step: 2
    action: await_analyst_approval
    gate: "DBA / SOC Lead"`
    }
  },
  {
    playbook_id: 11,
    name: "Supply Chain Dependency Tampering",
    target_threat: "Supply Chain Attack",
    execution_mode: "HITL",
    is_active: false,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1195",
      picerl_phase: "Eradication",
      language: "yaml",
      code: `name: Supply Chain Dependency Tampering
mitre_technique: T1195
execution_mode: HITL
steps:
  - step: 1
    action: quarantine_file
    connector: edr
  - step: 2
    action: await_analyst_approval
    gate: "AppSec Team"`
    }
  },
  {
    playbook_id: 12,
    name: "Insider Threat Privilege Abuse",
    target_threat: "Insider Threat",
    execution_mode: "HITL",
    is_active: true,
    created_at: new Date().toISOString(),
    workflow_logic: {
      mitre_id: "T1078",
      picerl_phase: "Containment",
      language: "yaml",
      code: `name: Insider Threat Privilege Abuse
mitre_technique: T1078
execution_mode: HITL
steps:
  - step: 1
    action: revoke_user_sessions
    connector: iam
  - step: 2
    action: await_analyst_approval
    gate: "HR & Security Director"`
    }
  }
];

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>(INITIAL_PLAYBOOKS);
  const [loading, setLoading] = useState<boolean>(true);
  const [modeFilter, setModeFilter] = useState<string>("ALL");
  const [currentUser, setCurrentUser] = useState<User | null>(null);

  useEffect(() => {
    const user = getStoredUser();
    setCurrentUser(user);

    const unsubscribe = subscribeToAuth((updatedUser) => {
      setCurrentUser(updatedUser);
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const canEditPlaybooks = Boolean(
    currentUser && (
      currentUser.role.toLowerCase().includes("admin") ||
      currentUser.role.toLowerCase().includes("engineer") ||
      currentUser.role.toLowerCase().includes("eng") ||
      currentUser.role.toLowerCase().includes("lead") ||
      currentUser.role.toLowerCase().includes("architect")
    )
  );

  // =========================================================================
  // OBJECTIVE 5: Power Toggle State Handler
  // =========================================================================
  const [powerStates, setPowerStates] = useState<Record<number, boolean>>(() => {
    const initialMap: Record<number, boolean> = {};
    INITIAL_PLAYBOOKS.forEach((p) => {
      initialMap[p.playbook_id] = p.is_active;
    });
    return initialMap;
  });

  // =========================================================================
  // OBJECTIVE 4: Code Editor Modal States
  // =========================================================================
  const [isEditorOpen, setIsEditorOpen] = useState<boolean>(false);
  const [editingPlaybook, setEditingPlaybook] = useState<Playbook | null>(null);
  const [editorSourceCode, setEditorSourceCode] = useState<string>("");
  const [editorLanguage, setEditorLanguage] = useState<string>("yaml");
  const [copied, setCopied] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  // =========================================================================
  // Custom Playbook Creation States
  // =========================================================================
  const [isCreateModalOpen, setIsCreateModalOpen] = useState<boolean>(false);
  const [createName, setCreateName] = useState<string>("");
  const [createThreat, setCreateThreat] = useState<string>("Ransomware");
  const [createCustomThreat, setCreateCustomThreat] = useState<string>("");
  const [createMode, setCreateMode] = useState<ExecutionMode>("HOTL");
  const [createMitreId, setCreateMitreId] = useState<string>("T1486");
  const [createPicerlPhase, setCreatePicerlPhase] = useState<string>("Containment");
  const [createSeverityTrigger, setCreateSeverityTrigger] = useState<string>("Critical");
  const [createVtThreshold, setCreateVtThreshold] = useState<number>(60);
  const [createSteps, setCreateSteps] = useState<Array<{ id: number; action: string; connector: string; params: string }>>([
    { id: 1, action: "isolate_endpoint", connector: "edr", params: "kill_network: true" },
    { id: 2, action: "block_ip", connector: "firewall", params: "duration_hours: 48" },
  ]);
  const [createTab, setCreateTab] = useState<"builder" | "yaml">("builder");
  const [customYamlCode, setCustomYamlCode] = useState<string>("");
  const [createLoading, setCreateLoading] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createSuccessMsg, setCreateSuccessMsg] = useState<string | null>(null);

  const generateYamlFromSteps = () => {
    const finalThreat = createThreat === "Custom" ? createCustomThreat : createThreat;
    const stepsYaml = createSteps.map((st, idx) => `  - step: ${idx + 1}
    action: ${st.action}
    connector: ${st.connector}
    params: { ${st.params || "auto: true"} }`).join("\n");

    return `name: ${createName || "Custom Playbook"}
target_threat: ${finalThreat || "Threat"}
mitre_technique: ${createMitreId || "T1000"}
picerl_phase: ${createPicerlPhase}
execution_mode: ${createMode}
trigger_rules:
  severity: ${createSeverityTrigger}
  vt_threshold: ${createVtThreshold}
steps:
${stepsYaml}`;
  };

  const handleAddStep = () => {
    const nextId = (createSteps[createSteps.length - 1]?.id || 0) + 1;
    setCreateSteps([...createSteps, { id: nextId, action: "terminate_process", connector: "edr", params: "" }]);
  };

  const handleRemoveStep = (id: number) => {
    if (createSteps.length <= 1) return;
    setCreateSteps(createSteps.filter((s) => s.id !== id));
  };

  const handleUpdateStep = (id: number, field: string, val: string) => {
    setCreateSteps(createSteps.map((s) => s.id === id ? { ...s, [field]: val } : s));
  };

  const handleCreatePlaybook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createName.trim()) {
      setCreateError("Please specify a playbook name.");
      return;
    }
    setCreateLoading(true);
    setCreateError(null);

    const finalThreat = createThreat === "Custom" ? (createCustomThreat.trim() || "Custom Threat") : createThreat;
    const finalYaml = createTab === "yaml" && customYamlCode ? customYamlCode : generateYamlFromSteps();

    const workflowLogic = {
      mitre_id: createMitreId || "T1000",
      picerl_phase: createPicerlPhase,
      language: "yaml",
      code: finalYaml,
      trigger_rules: {
        severity: createSeverityTrigger,
        vt_threshold: createVtThreshold,
      },
      steps: createSteps.map((s, idx) => ({
        step: idx + 1,
        action: s.action,
        connector: s.connector,
        params: s.params,
      })),
    };

    try {
      const created = await api.createPlaybook({
        name: createName.trim(),
        target_threat: finalThreat,
        execution_mode: createMode,
        workflow_logic: workflowLogic,
        is_active: true,
      });

      setPlaybooks((prev) => [created, ...prev]);
      setPowerStates((prev) => ({ ...prev, [created.playbook_id]: true }));
      setCreateSuccessMsg(`Playbook "${created.name}" created and deployed successfully!`);
      setIsCreateModalOpen(false);
      setCreateName("");
      setCreateCustomThreat("");
      setTimeout(() => setCreateSuccessMsg(null), 4000);
    } catch (err: any) {
      setCreateError(err.message || "Failed to create playbook.");
    } finally {
      setCreateLoading(false);
    }
  };

  useEffect(() => {
    const fetchRemotePlaybooks = async () => {
      try {
        const remote = await api.getPlaybooks();
        if (remote && remote.length > 0) {
          setPlaybooks(remote);
          const stateMap: Record<number, boolean> = {};
          remote.forEach((p) => {
            stateMap[p.playbook_id] = p.is_active;
          });
          setPowerStates(stateMap);
        }
      } catch (err) {
        console.warn("Using pre-configured playbook catalog fallback:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchRemotePlaybooks();
  }, []);

  // =========================================================================
  // OBJECTIVE 5: Toggle Switch Function with Backend API Placeholder
  // =========================================================================
  const handlePowerToggle = async (e: React.MouseEvent, playbookId: number) => {
    e.stopPropagation(); // Prevent opening the editor modal on toggle click

    if (!canEditPlaybooks) {
      alert("Access Denied: Playbook execution modifications are restricted to System Administrators and Security Engineers. SOC Analysts have read-only access.");
      return;
    }

    const nextState = !powerStates[playbookId];

    // Optimistically update visual UI state (transitions gray to green)
    setPowerStates((prev) => ({
      ...prev,
      [playbookId]: nextState,
    }));

    setPlaybooks((prev) =>
      prev.map((p) =>
        p.playbook_id === playbookId ? { ...p, is_active: nextState } : p
      )
    );

    // =========================================================================
    // TODO: Add backend API call to update the playbook active status:
    // try {
    //   await fetch(`/api/playbooks/${playbookId}/toggle`, {
    //     method: "PATCH",
    //     headers: { "Content-Type": "application/json" },
    //   });
    // } catch (error) {
    //   console.error("Failed to update playbook active status in backend:", error);
    //   // Optionally revert state on network error
    // }
    // =========================================================================
    try {
      await api.togglePlaybook(playbookId);
    } catch (err) {
      console.warn("Backend toggle API failed or running offline. Local state updated.");
    }
  };

  // =========================================================================
  // OBJECTIVE 4: Open Code Editor Modal (Row click / Settings click)
  // =========================================================================
  const handleOpenCodeEditor = (pb: Playbook) => {
    setEditingPlaybook(pb);
    const logic = pb.workflow_logic;
    let codeStr = "";

    if (logic && typeof logic === "object" && logic.code) {
      codeStr = logic.code;
      setEditorLanguage(logic.language || "yaml");
    } else if (typeof logic === "string") {
      codeStr = logic;
      setEditorLanguage("json");
    } else {
      codeStr = JSON.stringify(logic || {}, null, 2);
      setEditorLanguage("json");
    }

    setEditorSourceCode(codeStr);
    setSaveSuccess(false);
    setIsEditorOpen(true);
  };

  // Save Code Editor Changes
  const handleSaveEditor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingPlaybook) return;

    if (!canEditPlaybooks) {
      alert("Access Denied: Playbook modifications are restricted to System Administrators and Security Engineers. SOC Analysts have read-only permissions.");
      return;
    }

    let updatedLogic: any;
    try {
      if (editorLanguage === "json") {
        updatedLogic = JSON.parse(editorSourceCode);
      } else {
        updatedLogic = {
          ...((typeof editingPlaybook.workflow_logic === "object" ? editingPlaybook.workflow_logic : {})),
          code: editorSourceCode,
          language: editorLanguage,
        };
      }
    } catch (err) {
      // Keep as string code representation
      updatedLogic = { code: editorSourceCode, language: editorLanguage };
    }

    // Update local state
    setPlaybooks((prev) =>
      prev.map((p) =>
        p.playbook_id === editingPlaybook.playbook_id
          ? { ...p, workflow_logic: updatedLogic }
          : p
      )
    );

    // Backend save call
    try {
      await api.updatePlaybook(editingPlaybook.playbook_id, {
        workflow_logic: updatedLogic,
      });
    } catch (err) {
      console.warn("Backend update API failed or running offline. Local state saved.");
    }

    setSaveSuccess(true);
    setTimeout(() => {
      setSaveSuccess(false);
      setIsEditorOpen(false);
    }, 800);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(editorSourceCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDelete = (e: React.MouseEvent, playbookId: number, name: string) => {
    e.stopPropagation();
    if (!canEditPlaybooks) {
      alert("Access Denied: Deleting playbooks is restricted to System Administrators and Security Engineers.");
      return;
    }
    if (!confirm(`Are you sure you want to delete playbook: "${name}"?`)) return;
    setPlaybooks((prev) => prev.filter((p) => p.playbook_id !== playbookId));
    api.deletePlaybook(playbookId).catch(() => {});
  };

  const filteredPlaybooks = playbooks.filter((p) => {
    if (modeFilter === "ALL") return true;
    return p.execution_mode.toUpperCase() === modeFilter.toUpperCase();
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2.5">
            <h1 className="text-2xl font-black text-white tracking-tight">
              Playbook Automation Catalog & Code Editor
            </h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-bold">
              {playbooks.length} Configured
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Standardized SANS PICERL & MITRE ATT&CK incident response orchestration logic. Click any playbook or settings button to edit code.
          </p>
        </div>

        {/* Header Actions: Create Button + Filter Pills */}
        <div className="flex items-center space-x-3">
          {canEditPlaybooks ? (
            <button
              onClick={() => {
                setCustomYamlCode(generateYamlFromSteps());
                setIsCreateModalOpen(true);
              }}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-blue-600/25 transition transform hover:-translate-y-0.5 flex-shrink-0"
            >
              <Plus className="h-4 w-4" />
              <span>Create Custom Playbook</span>
            </button>
          ) : (
            <div className="flex items-center space-x-1.5 px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-medium text-slate-400 flex-shrink-0">
              <Lock className="h-3.5 w-3.5 text-amber-400" />
              <span>Playbooks Read-Only (Sec Eng / Sys Admin only)</span>
            </div>
          )}

          {/* Filter Pills */}
          <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 p-1.5 rounded-xl text-xs">
            {["ALL", "HOTL", "HITL"].map((m) => (
              <button
                key={m}
                onClick={() => setModeFilter(m)}
                className={`px-3 py-1.5 rounded-lg font-bold text-[11px] transition ${
                  modeFilter === m
                    ? "bg-blue-600 text-white shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {m === "ALL" ? "All Playbooks" : `${m} Mode`}
              </button>
            ))}
          </div>
        </div>
      </div>

      {createSuccessMsg && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
          <span>{createSuccessMsg}</span>
        </div>
      )}

      {/* Grid of Playbook Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredPlaybooks.map((pb) => {
          const isPowered = powerStates[pb.playbook_id] ?? pb.is_active;
          const isHOTL = pb.execution_mode.toUpperCase() === "HOTL";
          const logic = typeof pb.workflow_logic === "string" 
            ? JSON.parse(pb.workflow_logic || "{}") 
            : (pb.workflow_logic || {});
          const mitreId = logic?.mitre_id || "T1000";
          const picerl = logic?.picerl_phase || "Containment";

          return (
            /* ========================================================================= */
            /* OBJECTIVE 3: STRICT CONTAINER BOUNDS & NO OVERFLOW                         */
            /* ========================================================================= */
            <div
              key={pb.playbook_id}
              onClick={() => handleOpenCodeEditor(pb)}
              className="flex flex-col overflow-hidden bg-slate-900 border border-slate-800 rounded-xl shadow-lg hover:border-slate-700 transition cursor-pointer group relative"
            >
              {/* Card Header & Body */}
              <div className="p-5 flex-1 space-y-3 overflow-hidden">
                {/* Header row with Title and Badges */}
                <div className="flex items-start justify-between gap-2 overflow-hidden">
                  <div className="space-y-1 min-w-0 flex-1">
                    {/* Fixed ID 1 & ID 2 overlap: cleanly flex-wrapped with proper margins */}
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
                      isHOTL
                        ? "bg-blue-500/10 text-blue-400 border-blue-500/30"
                        : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                    }`}
                  >
                    {pb.execution_mode}
                  </span>
                </div>

                {/* SANS PICERL & MITRE Tags */}
                <div className="pt-2 border-t border-slate-800/80 space-y-2 text-xs">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>SANS IR Phase:</span>
                    <span className="font-semibold text-emerald-400">{picerl}</span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>MITRE Technique:</span>
                    <span className="font-mono text-purple-400 font-semibold">{mitreId}</span>
                  </div>
                </div>
              </div>

              {/* ========================================================================= */}
              {/* OBJECTIVE 3: FIXED PLAYBOOK FOOTER & SETTINGS BUTTON CONTAINMENT           */}
              {/* OBJECTIVE 5: INTERACTIVE POWER TOGGLE SWITCH                               */}
              {/* ========================================================================= */}
              <div className="px-4 py-3 bg-slate-950/80 border-t border-slate-800 flex items-center justify-between gap-2 overflow-hidden flex-shrink-0">
                {/* Status indicator */}
                <div className="flex items-center space-x-2 flex-shrink-0">
                  <span
                    className={`h-2 w-2 rounded-full ${
                      isPowered ? "bg-emerald-400 animate-pulse" : "bg-slate-600"
                    }`}
                  />
                  <span className="text-[11px] font-medium text-slate-400">
                    {isPowered ? "Active" : "Disabled"}
                  </span>
                </div>

                {/* Actions Bar: Power Toggle, Settings Button, Delete Button */}
                <div className="flex items-center space-x-2 flex-shrink-0">
                  {/* OBJECTIVE 5: Power Toggle Switch */}
                  <button
                    type="button"
                    role="switch"
                    aria-checked={isPowered}
                    disabled={!canEditPlaybooks}
                    onClick={(e) => handlePowerToggle(e, pb.playbook_id)}
                    className={`relative inline-flex h-5 w-10 flex-shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                      !canEditPlaybooks ? "cursor-not-allowed opacity-50" : "cursor-pointer"
                    } ${
                      isPowered ? "bg-emerald-500" : "bg-slate-700"
                    }`}
                    title={
                      !canEditPlaybooks 
                        ? "Restricted: Only System Administrators and Security Engineers can toggle playbooks." 
                        : isPowered ? "Disable Playbook" : "Enable Playbook"
                    }
                  >
                    <span
                      aria-hidden="true"
                      className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                        isPowered ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </button>

                  {/* OBJECTIVE 3 & 4: Settings Button cleanly contained with flex-shrink-0 */}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleOpenCodeEditor(pb);
                    }}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 transition flex-shrink-0"
                    title={canEditPlaybooks ? "Open Playbook Code Editor" : "Inspect Playbook Code (Read-Only)"}
                  >
                    <Settings className="h-3.5 w-3.5 text-blue-400" />
                  </button>

                  {/* Delete button (restricted to Sec Eng & Sys Admin) */}
                  {canEditPlaybooks && (
                    <button
                      type="button"
                      onClick={(e) => handleDelete(e, pb.playbook_id, pb.name)}
                      className="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-600 text-rose-400 hover:text-white border border-rose-500/20 transition flex-shrink-0"
                      title="Delete Playbook"
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

      {/* ========================================================================= */}
      {/* OBJECTIVE 4: PLAYBOOK CODE EDITOR MODAL                                    */}
      {/* ========================================================================= */}
      {isEditorOpen && editingPlaybook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div 
            className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[92vh] flex flex-col shadow-2xl shadow-black overflow-hidden relative"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="p-5 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="h-9 w-9 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
                  <Code className="h-4 w-4 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                    <span>Source Code Editor:</span>
                    <span className="text-blue-400">{editingPlaybook.name}</span>
                  </h2>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    ID #{editingPlaybook.playbook_id} | Mode: {editingPlaybook.execution_mode} | Threat: {editingPlaybook.target_threat}
                  </p>
                </div>
              </div>

              {/* Close Button */}
              <button
                onClick={() => setIsEditorOpen(false)}
                className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition border border-slate-700/60"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Code Editor Form */}
            <form onSubmit={handleSaveEditor} className="flex-1 overflow-y-auto p-6 space-y-4 flex flex-col">
              {!canEditPlaybooks && (
                <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center space-x-2.5">
                  <Lock className="h-4 w-4 text-amber-400 flex-shrink-0" />
                  <span>
                    <strong>Read-Only Mode:</strong> Your role (<strong>{currentUser?.role || "SOC Analyst"}</strong>) is restricted from modifying automated playbooks. Playbook changes are restricted exclusively to System Administrators and Security Engineers.
                  </span>
                </div>
              )}

              <div className="flex items-center justify-between text-xs text-slate-400">
                <div className="flex items-center space-x-2">
                  <span className="font-semibold text-slate-300">Format:</span>
                  <div className="flex items-center bg-slate-950 rounded-lg p-0.5 border border-slate-800">
                    <button
                      type="button"
                      onClick={() => setEditorLanguage("yaml")}
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        editorLanguage === "yaml" ? "bg-blue-600 text-white" : "text-slate-400"
                      }`}
                    >
                      YAML
                    </button>
                    <button
                      type="button"
                      onClick={() => setEditorLanguage("json")}
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        editorLanguage === "json" ? "bg-blue-600 text-white" : "text-slate-400"
                      }`}
                    >
                      JSON
                    </button>
                    <button
                      type="button"
                      onClick={() => setEditorLanguage("python")}
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        editorLanguage === "python" ? "bg-blue-600 text-white" : "text-slate-400"
                      }`}
                    >
                      Python
                    </button>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleCopyCode}
                  className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
                >
                  {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  <span>{copied ? "Copied" : "Copy Code"}</span>
                </button>
              </div>

              {/* Editable Textarea */}
              <div className="flex-1 min-h-[340px] relative">
                <textarea
                  value={editorSourceCode}
                  onChange={(e) => setEditorSourceCode(e.target.value)}
                  readOnly={!canEditPlaybooks}
                  className={`w-full h-full min-h-[340px] bg-slate-950 font-mono text-xs text-slate-200 border border-slate-800 rounded-xl p-4 focus:outline-none focus:border-blue-500 leading-relaxed resize-y selection:bg-blue-600 selection:text-white ${
                    !canEditPlaybooks ? "cursor-default opacity-85 focus:border-slate-800" : ""
                  }`}
                  spellCheck={false}
                  placeholder="# Enter playbook orchestration source code..."
                />
              </div>

              {/* Editor Actions Footer */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">
                  {canEditPlaybooks 
                    ? "Tip: Edit the playbook containment steps and trigger parameters. Click Save to persist." 
                    : "Read-only inspection. You cannot edit or save playbook logic."}
                </span>

                <div className="flex items-center space-x-3">
                  <button
                    type="button"
                    onClick={() => setIsEditorOpen(false)}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
                  >
                    {canEditPlaybooks ? "Cancel" : "Close"}
                  </button>

                  {canEditPlaybooks && (
                    <button
                      type="submit"
                      className="flex items-center space-x-1.5 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition transform hover:-translate-y-0.5"
                    >
                      <Save className="h-3.5 w-3.5" />
                      <span>{saveSuccess ? "Saved!" : "Save Changes"}</span>
                    </button>
                  )}
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* CUSTOM PLAYBOOK CREATOR MODAL                                              */}
      {/* ========================================================================= */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center space-x-3">
                <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
                  <Plus className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white tracking-wide">
                    Create Custom Automation Playbook
                  </h2>
                  <p className="text-xs text-slate-400">
                    Define threat targets, execution modes, automated rules, and containment actions.
                  </p>
                </div>
              </div>

              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition border border-slate-700/60"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Error Notice */}
            {createError && (
              <div className="m-5 mb-0 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center space-x-2">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{createError}</span>
              </div>
            )}

            {/* Tab Selector */}
            <div className="px-6 pt-4 flex items-center space-x-2 border-b border-slate-800 bg-slate-950/30">
              <button
                type="button"
                onClick={() => setCreateTab("builder")}
                className={`flex items-center space-x-2 px-4 py-2 text-xs font-bold border-b-2 transition ${
                  createTab === "builder"
                    ? "border-blue-500 text-blue-400 bg-blue-500/10 rounded-t-lg"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <Layers className="h-3.5 w-3.5" />
                <span>Visual Rule & Action Builder</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setCustomYamlCode(generateYamlFromSteps());
                  setCreateTab("yaml");
                }}
                className={`flex items-center space-x-2 px-4 py-2 text-xs font-bold border-b-2 transition ${
                  createTab === "yaml"
                    ? "border-blue-500 text-blue-400 bg-blue-500/10 rounded-t-lg"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <FileCode className="h-3.5 w-3.5" />
                <span>YAML / Code View</span>
              </button>
            </div>

            {/* Form Content */}
            <form onSubmit={handleCreatePlaybook} className="flex-1 overflow-y-auto p-6 space-y-5">
              {createTab === "builder" ? (
                <>
                  {/* Section 1: Playbook Metadata */}
                  <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Cpu className="h-3.5 w-3.5 text-blue-400" />
                      1. General Playbook Identity
                    </h3>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                      <div className="space-y-1 sm:col-span-2">
                        <label className="text-xs font-semibold text-slate-300">Playbook Name *</label>
                        <input
                          type="text"
                          required
                          value={createName}
                          onChange={(e) => setCreateName(e.target.value)}
                          placeholder="e.g. Web Shell & Remote Code Execution Blocker"
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-medium"
                        />
                      </div>

                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">Target Threat Category</label>
                        <select
                          value={createThreat}
                          onChange={(e) => setCreateThreat(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-medium"
                        >
                          <option value="Ransomware">Ransomware</option>
                          <option value="Phishing">Phishing</option>
                          <option value="Brute Force">Brute Force</option>
                          <option value="Web Attack">Web Attack / SQLi</option>
                          <option value="Lateral Movement">Lateral Movement</option>
                          <option value="Credential Access">Credential Access / Mimikatz</option>
                          <option value="Data Exfiltration">Data Exfiltration</option>
                          <option value="Zero-Day">Zero-Day Exploit</option>
                          <option value="Custom">Custom Threat Name</option>
                        </select>
                      </div>

                      {createThreat === "Custom" && (
                        <div className="space-y-1">
                          <label className="text-xs font-semibold text-slate-300">Custom Threat Name *</label>
                          <input
                            type="text"
                            required
                            value={createCustomThreat}
                            onChange={(e) => setCreateCustomThreat(e.target.value)}
                            placeholder="e.g. Cloud Cryptojacking"
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-medium"
                          />
                        </div>
                      )}

                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">Execution Mode</label>
                        <select
                          value={createMode}
                          onChange={(e) => setCreateMode(e.target.value as ExecutionMode)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-medium"
                        >
                          <option value="HOTL">HOTL (Autonomous / Instant Containment)</option>
                          <option value="HITL">HITL (Human-in-the-Loop Analyst Gate)</option>
                        </select>
                      </div>

                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">SANS PICERL Phase</label>
                        <select
                          value={createPicerlPhase}
                          onChange={(e) => setCreatePicerlPhase(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-medium"
                        >
                          <option value="Containment">Containment</option>
                          <option value="Identification">Identification</option>
                          <option value="Eradication">Eradication</option>
                          <option value="Recovery">Recovery</option>
                        </select>
                      </div>

                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">MITRE ATT&CK Technique</label>
                        <input
                          type="text"
                          value={createMitreId}
                          onChange={(e) => setCreateMitreId(e.target.value)}
                          placeholder="e.g. T1190, T1059"
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Section 2: Trigger Rules */}
                  <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Zap className="h-3.5 w-3.5 text-amber-400" />
                      2. Playbook Trigger Rules (Defined by You)
                    </h3>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">Trigger on Minimum Severity</label>
                        <select
                          value={createSeverityTrigger}
                          onChange={(e) => setCreateSeverityTrigger(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-medium"
                        >
                          <option value="Critical">Critical Severity</option>
                          <option value="High">High Severity & Above</option>
                          <option value="Medium">Medium Severity & Above</option>
                          <option value="Low">Low Severity & Above</option>
                        </select>
                      </div>

                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-300">Threat Intel Minimum VT Score</label>
                        <input
                          type="number"
                          min="0"
                          max="100"
                          value={createVtThreshold}
                          onChange={(e) => setCreateVtThreshold(parseInt(e.target.value) || 0)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Section 3: Action Sequence Steps */}
                  <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        3. Automated Containment Actions & Steps ({createSteps.length})
                      </h3>

                      <button
                        type="button"
                        onClick={handleAddStep}
                        className="flex items-center space-x-1 px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-xs font-semibold transition"
                      >
                        <Plus className="h-3 w-3" />
                        <span>Add Action Step</span>
                      </button>
                    </div>

                    <div className="space-y-2.5">
                      {createSteps.map((step, idx) => (
                        <div
                          key={step.id}
                          className="p-3 bg-slate-900 rounded-xl border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                        >
                          <div className="flex items-center space-x-2">
                            <span className="h-6 w-6 rounded-lg bg-blue-600/20 text-blue-400 text-xs font-bold flex items-center justify-center font-mono">
                              {idx + 1}
                            </span>
                            <span className="text-xs text-slate-300 font-bold">Action:</span>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 flex-1 w-full sm:w-auto">
                            <select
                              value={step.action}
                              onChange={(e) => handleUpdateStep(step.id, "action", e.target.value)}
                              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-medium"
                            >
                              <option value="isolate_endpoint">isolate_endpoint (EDR)</option>
                              <option value="terminate_process">terminate_process (EDR)</option>
                              <option value="block_ip">block_ip (Firewall)</option>
                              <option value="apply_rate_limit">apply_rate_limit (Firewall)</option>
                              <option value="revoke_user_sessions">revoke_user_sessions (IAM)</option>
                              <option value="disable_user_account">disable_user_account (IAM)</option>
                              <option value="query_virustotal">query_virustotal (TIP)</option>
                              <option value="create_jira_ticket">create_jira_ticket (ITSM)</option>
                              <option value="send_slack_alert">send_slack_alert (ITSM)</option>
                              <option value="generate_pdf_report">generate_pdf_report (ReportLab)</option>
                            </select>

                            <select
                              value={step.connector}
                              onChange={(e) => handleUpdateStep(step.id, "connector", e.target.value)}
                              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono"
                            >
                              <option value="edr">edr</option>
                              <option value="firewall">firewall</option>
                              <option value="iam">iam</option>
                              <option value="tip">tip</option>
                              <option value="itsm">itsm</option>
                              <option value="reporter">reporter</option>
                            </select>

                            <input
                              type="text"
                              value={step.params}
                              onChange={(e) => handleUpdateStep(step.id, "params", e.target.value)}
                              placeholder="params (e.g. kill_network: true)"
                              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono placeholder-slate-600"
                            />
                          </div>

                          {createSteps.length > 1 && (
                            <button
                              type="button"
                              onClick={() => handleRemoveStep(step.id)}
                              className="p-1.5 text-slate-500 hover:text-rose-400 rounded-lg hover:bg-slate-800 transition"
                              title="Delete Step"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                /* YAML View Tab */
                <div className="space-y-2">
                  <div className="text-xs text-slate-400 flex items-center justify-between">
                    <span>Direct Playbook Orchestration Code (YAML):</span>
                    <span className="font-mono text-[11px] text-blue-400">format: yaml</span>
                  </div>
                  <textarea
                    rows={16}
                    value={customYamlCode}
                    onChange={(e) => setCustomYamlCode(e.target.value)}
                    className="w-full bg-slate-950 font-mono text-xs text-emerald-400 border border-slate-800 rounded-xl p-4 focus:outline-none focus:border-blue-500 leading-relaxed"
                    spellCheck={false}
                  />
                </div>
              )}

              {/* Submit Footer */}
              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">
                  New playbooks are automatically activated and loaded into the SOC runner engine.
                </span>

                <div className="flex items-center space-x-3">
                  <button
                    type="button"
                    onClick={() => setIsCreateModalOpen(false)}
                    className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
                  >
                    Cancel
                  </button>

                  <button
                    type="submit"
                    disabled={createLoading}
                    className="flex items-center space-x-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition transform hover:-translate-y-0.5 disabled:opacity-50"
                  >
                    {createLoading ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Plus className="h-3.5 w-3.5" />
                    )}
                    <span>{createLoading ? "Creating Playbook..." : "Save & Deploy Playbook"}</span>
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
