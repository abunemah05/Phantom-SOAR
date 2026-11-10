"use client";

import React, { useState, useEffect } from "react";
import { X, Save, AlertCircle, Code, Layers, ShieldCheck } from "lucide-react";
import { Playbook, ExecutionMode } from "@/lib/types";
import { api } from "@/lib/api";

interface PlaybookModalProps {
  isOpen: boolean;
  onClose: () => void;
  playbook: Playbook | null;
  onSaved: () => void;
  templates?: any[];
}

export default function PlaybookModal({
  isOpen,
  onClose,
  playbook,
  onSaved,
  templates = [],
}: PlaybookModalProps) {
  const [name, setName] = useState<string>("");
  const [targetThreat, setTargetThreat] = useState<string>("");
  const [executionMode, setExecutionMode] = useState<ExecutionMode>("HOTL");
  const [workflowJson, setWorkflowJson] = useState<string>("{\n  \"steps\": []\n}");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    if (playbook) {
      setName(playbook.name);
      setTargetThreat(playbook.target_threat);
      setExecutionMode(playbook.execution_mode);
      const jsonStr = typeof playbook.workflow_logic === "string" 
        ? playbook.workflow_logic 
        : JSON.stringify(playbook.workflow_logic, null, 2);
      setWorkflowJson(jsonStr);
      setJsonError(null);
    } else {
      setName("");
      setTargetThreat("");
      setExecutionMode("HOTL");
      setWorkflowJson(JSON.stringify({
        mitre_id: "T1000",
        picerl_phase: "Containment",
        steps: [
          { order: 1, action: "isolate_endpoint", connector: "edr" },
          { order: 2, action: "block_ip", connector: "firewall" },
          { order: 3, action: "generate_report", connector: "reporter" }
        ]
      }, null, 2));
      setJsonError(null);
    }
  }, [playbook, isOpen]);

  if (!isOpen) return null;

  const handleTemplateSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selectedIndex = parseInt(e.target.value, 10);
    if (isNaN(selectedIndex) || !templates[selectedIndex]) return;
    const t = templates[selectedIndex];
    setName(t.name);
    setTargetThreat(t.target_threat);
    setExecutionMode(t.execution_mode);
    setWorkflowJson(JSON.stringify(t.workflow_logic, null, 2));
    setJsonError(null);
  };

  const handleJsonChange = (val: string) => {
    setWorkflowJson(val);
    try {
      JSON.parse(val);
      setJsonError(null);
    } catch (e: any) {
      setJsonError(e.message);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    let parsedWorkflow;
    try {
      parsedWorkflow = JSON.parse(workflowJson);
    } catch (e: any) {
      setJsonError("Invalid JSON syntax: " + e.message);
      return;
    }

    setLoading(true);
    try {
      if (playbook) {
        // Update existing playbook (PUT)
        await api.updatePlaybook(playbook.playbook_id, {
          name,
          target_threat: targetThreat,
          execution_mode: executionMode,
          workflow_logic: parsedWorkflow,
        });
      } else {
        // Create new playbook (POST)
        await api.createPlaybook({
          name,
          target_threat: targetThreat,
          execution_mode: executionMode,
          workflow_logic: parsedWorkflow,
          is_active: true,
        });
      }
      onSaved();
      onClose();
    } catch (err: any) {
      alert("Error saving playbook: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div 
        className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[92vh] flex flex-col shadow-2xl shadow-black overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
              <Code className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide">
                {playbook ? `Edit Playbook #${playbook.playbook_id}` : "Configure New IR Playbook"}
              </h2>
              <p className="text-xs text-slate-400">
                SANS PICERL / SOAPA Orchestration Logic Editor
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSave} className="flex-1 overflow-y-auto p-6 space-y-4">
          {/* Template Dropdown */}
          {!playbook && templates.length > 0 && (
            <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800 space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Layers className="h-3.5 w-3.5 text-blue-400" />
                Populate from Pre-configured SANS / MITRE Template:
              </label>
              <select
                onChange={handleTemplateSelect}
                defaultValue=""
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="" disabled>-- Select one of 12 IR Playbook Templates --</option>
                {templates.map((tpl, idx) => (
                  <option key={idx} value={idx}>
                    [{tpl.execution_mode}] {tpl.name} ({tpl.target_threat})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Playbook Name */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Playbook Name</label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Ransomware Outbreak Containment"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Target Threat */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Target Threat Category</label>
              <input
                type="text"
                required
                value={targetThreat}
                onChange={(e) => setTargetThreat(e.target.value)}
                placeholder="e.g., Ransomware, Phishing, WebShell"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Execution Mode */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Execution Mode</label>
              <select
                value={executionMode}
                onChange={(e) => setExecutionMode(e.target.value as ExecutionMode)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="HOTL">HOTL (Autonomous / Human-On-The-Loop)</option>
                <option value="HITL">HITL (Manual Approval / Human-In-The-Loop)</option>
              </select>
            </div>
          </div>

          {/* JSON Workflow Editor */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Code className="h-3.5 w-3.5 text-blue-400" />
                Workflow Orchestration Logic (JSON)
              </label>
              {jsonError ? (
                <span className="text-[11px] text-rose-400 flex items-center gap-1">
                  <AlertCircle className="h-3 w-3" />
                  JSON Syntax Error
                </span>
              ) : (
                <span className="text-[11px] text-emerald-400 flex items-center gap-1">
                  <ShieldCheck className="h-3 w-3" />
                  Valid JSON
                </span>
              )}
            </div>
            <textarea
              rows={10}
              required
              value={workflowJson}
              onChange={(e) => handleJsonChange(e.target.value)}
              className={`w-full font-mono text-xs bg-slate-950 rounded-lg p-3.5 text-slate-200 border focus:outline-none transition ${
                jsonError ? "border-rose-500/60 focus:border-rose-500" : "border-slate-800 focus:border-blue-500"
              }`}
              spellCheck={false}
            />
            {jsonError && (
              <p className="text-[11px] text-rose-400 font-mono mt-1">{jsonError}</p>
            )}
          </div>

          {/* Footer Actions */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || Boolean(jsonError)}
              className="flex items-center space-x-1.5 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-bold text-white shadow-lg shadow-blue-600/30 transition disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" />
              <span>{loading ? "Saving..." : playbook ? "Save Changes" : "Create Playbook"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
