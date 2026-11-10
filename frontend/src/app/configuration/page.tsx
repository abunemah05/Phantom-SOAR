"use client";

import React, { useState, useEffect } from "react";
import { 
  Sliders, 
  Key, 
  Cpu, 
  ShieldCheck, 
  Database, 
  Radio, 
  Network, 
  Bell, 
  CheckCircle2, 
  AlertCircle, 
  Save, 
  Eye, 
  EyeOff, 
  Activity, 
  RefreshCw,
  Sparkles,
  Server,
  XCircle,
  AlertTriangle
} from "lucide-react";
import { api } from "@/lib/api";
import { SystemConfigGroup, TestConnectionResult } from "@/lib/types";

interface SectionField {
  key_name: string;
  label: string;
  placeholder: string;
  is_secret?: boolean;
}

interface IntegrationCard {
  id: string;
  category: string;
  title: string;
  description: string;
  icon: React.ElementType;
  fields: SectionField[];
}

const INTEGRATION_SECTIONS: IntegrationCard[] = [
  {
    id: "ai",
    category: "AI",
    title: "AI / LLM Orchestration Engine",
    description: "Automated executive incident triage briefs, MITRE ATT&CK correlation, and intelligent containment suggestions.",
    icon: Sparkles,
    fields: [
      { key_name: "ai_provider", label: "AI Provider Engine", placeholder: "Google Gemini / OpenAI / Anthropic / Ollama" },
      { key_name: "ai_model", label: "Model Architecture", placeholder: "gemini-1.5-pro / gpt-4o" },
      { key_name: "ai_api_key", label: "API Key / Auth Secret", placeholder: "Enter real production API key...", is_secret: true },
      { key_name: "ai_endpoint", label: "API Base URL", placeholder: "https://generativelanguage.googleapis.com / https://api.openai.com/v1" }
    ]
  },
  {
    id: "edr",
    category: "EDR",
    title: "EDR (Endpoint Detection & Response)",
    description: "Host isolation, remote process tree termination, memory dumps, and kernel-level quarantine.",
    icon: Cpu,
    fields: [
      { key_name: "edr_provider", label: "EDR Agent Provider", placeholder: "CrowdStrike Falcon / Microsoft Defender / Wazuh Active Response" },
      { key_name: "edr_base_url", label: "EDR Management URL", placeholder: "https://api.crowdstrike.com" },
      { key_name: "edr_api_key", label: "EDR Client Secret / API Key", placeholder: "Enter EDR API key...", is_secret: true }
    ]
  },
  {
    id: "xdr",
    category: "XDR",
    title: "XDR (Extended Detection & Response)",
    description: "Cross-layer correlation across endpoint, identity, cloud workloads, and network telemetry.",
    icon: ShieldCheck,
    fields: [
      { key_name: "xdr_provider", label: "XDR Solution", placeholder: "Palo Alto Cortex XDR / Trend Micro Vision One" },
      { key_name: "xdr_tenant_url", label: "XDR Tenant Gateway", placeholder: "https://api-enterprise.xdr.paloaltonetworks.com" },
      { key_name: "xdr_api_key", label: "XDR API Key / Secret", placeholder: "Enter Cortex XDR API key...", is_secret: true }
    ]
  },
  {
    id: "siem",
    category: "SIEM",
    title: "SIEM (Security Information & Event Management)",
    description: "Ingestion gateway for Wazuh SIEM alerts, agent status monitoring, and syslog forwarding.",
    icon: Database,
    fields: [
      { key_name: "siem_provider", label: "SIEM Architecture", placeholder: "Wazuh SIEM Manager v4.7+" },
      { key_name: "siem_manager_url", label: "Wazuh Manager REST URL", placeholder: "https://10.0.0.10:55000" },
      { key_name: "siem_user", label: "API Username", placeholder: "wazuh-api-admin" },
      { key_name: "siem_password", label: "API Secret / Password", placeholder: "Enter Wazuh API password...", is_secret: true }
    ]
  },
  {
    id: "tip",
    category: "TIP",
    title: "TIP (Threat Intelligence Platforms)",
    description: "Automated reputation scoring, IoC lookups against VirusTotal v3 and AbuseIPDB.",
    icon: Radio,
    fields: [
      { key_name: "virustotal_api_key", label: "VirusTotal v3 API Key", placeholder: "Enter real 64-char VT key...", is_secret: true },
      { key_name: "abuseipdb_api_key", label: "AbuseIPDB API Key", placeholder: "Enter AbuseIPDB key...", is_secret: true },
      { key_name: "otx_api_key", label: "AlienVault OTX Key (Optional)", placeholder: "Enter OTX key...", is_secret: true }
    ]
  },
  {
    id: "firewall",
    category: "FIREWALL",
    title: "Firewall & Perimeter Edge",
    description: "Dynamic perimeter IP blocking, rate limiting, and ACL synchronization with edge appliances.",
    icon: Network,
    fields: [
      { key_name: "firewall_provider", label: "Perimeter Appliance", placeholder: "Palo Alto Panorama / Fortinet FortiGate / pfSense" },
      { key_name: "firewall_host", label: "Management IP / Hostname", placeholder: "https://192.168.1.1" },
      { key_name: "firewall_api_key", label: "Admin API Token", placeholder: "Enter firewall API token...", is_secret: true }
    ]
  },
  {
    id: "itsm",
    category: "ITSM",
    title: "ITSM & Alert Notification Webhooks",
    description: "Automated Jira incident ticket creation, SLA timers, and Slack / Teams SOC channels.",
    icon: Bell,
    fields: [
      { key_name: "jira_webhook_url", label: "Jira Service Management Webhook", placeholder: "https://your-domain.atlassian.net/webhook" },
      { key_name: "slack_webhook_url", label: "Slack / Teams Alert Channel Webhook", placeholder: "https://hooks.slack.com/services/...", is_secret: true }
    ]
  }
];

export default function ConfigurationPage() {
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [visibleSecrets, setVisibleSecrets] = useState<Record<string, boolean>>({});
  const [testResults, setTestResults] = useState<Record<string, TestConnectionResult>>({});
  const [testingId, setTestingId] = useState<string | null>(null);
  const [saving, setSaving] = useState<boolean>(false);
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  useEffect(() => {
    const loadConfig = async () => {
      try {
        const data = await api.getConfigurations();
        const initialVals: Record<string, string> = {};
        Object.entries(data).forEach(([cat, keys]) => {
          Object.entries(keys).forEach(([k, entry]) => {
            initialVals[`${cat.toUpperCase()}_${k}`] = entry.value || "";
          });
        });
        setFormValues(initialVals);
      } catch (err) {
        console.warn("Could not load backend configurations.");
      }
    };
    loadConfig();
  }, []);

  const handleChange = (category: string, keyName: string, value: string) => {
    setFormValues((prev) => ({
      ...prev,
      [`${category.toUpperCase()}_${keyName}`]: value,
    }));
  };

  const toggleSecretVisibility = (fieldKey: string) => {
    setVisibleSecrets((prev) => ({
      ...prev,
      [fieldKey]: !prev[fieldKey],
    }));
  };

  const handleTestConnection = async (card: IntegrationCard) => {
    setTestingId(card.id);
    try {
      // Find secret key
      const secretField = card.fields.find((f) => f.is_secret)?.key_name;
      const apiKeyVal = secretField ? (formValues[`${card.category}_${secretField}`] || "") : "";

      // Find URL / host field
      const urlField = card.fields.find(
        (f) => f.key_name.includes("url") || f.key_name.includes("host") || f.key_name.includes("endpoint")
      )?.key_name;
      const endpointVal = urlField ? (formValues[`${card.category}_${urlField}`] || "") : "";

      const res = await api.testConnection(card.category, card.title, apiKeyVal, endpointVal);
      setTestResults((prev) => ({
        ...prev,
        [card.id]: res,
      }));
    } catch (err: any) {
      setTestResults((prev) => ({
        ...prev,
        [card.id]: {
          status: "Connection Failed",
          is_connected: false,
          service_name: card.title,
          category: card.category,
          latency_ms: 0,
          health: "Network / Transport Error",
          message: err.message || "Failed to reach SOAR backend connector.",
        },
      }));
    } finally {
      setTestingId(null);
    }
  };

  const handleSaveAll = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedSuccess(false);

    const configsToSave: Array<{ category: string; key_name: string; key_value: string; is_secret: boolean }> = [];

    INTEGRATION_SECTIONS.forEach((section) => {
      section.fields.forEach((field) => {
        const fieldKey = `${section.category}_${field.key_name}`;
        configsToSave.push({
          category: section.category,
          key_name: field.key_name,
          key_value: formValues[fieldKey] || "",
          is_secret: !!field.is_secret,
        });
      });
    });

    try {
      await api.updateConfigurations(configsToSave);
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 4000);
    } catch (err) {
      alert("Failed to save configurations.");
    } finally {
      setSaving(false);
    }
  };

  // Dynamically compute badge status for each card
  const getCardStatusBadge = (card: IntegrationCard) => {
    const result = testResults[card.id];
    if (result) {
      if (result.is_connected && result.status === "Connected") {
        return {
          label: "Connected (200 OK)",
          badgeColor: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
        };
      }
      if (result.status === "Not Configured") {
        return {
          label: "Not Configured",
          badgeColor: "bg-slate-800 text-slate-400 border-slate-700",
        };
      }
      if (result.status === "Unreachable") {
        return {
          label: "Unreachable",
          badgeColor: "bg-amber-500/10 text-amber-400 border-amber-500/30",
        };
      }
      return {
        label: "Auth Failed (401)",
        badgeColor: "bg-rose-500/10 text-rose-400 border-rose-500/30",
      };
    }

    // Prior to testing, check if any credential is filled
    const secretField = card.fields.find((f) => f.is_secret)?.key_name;
    const secretVal = secretField ? formValues[`${card.category}_${secretField}`] : "";
    const urlField = card.fields.find(
      (f) => f.key_name.includes("url") || f.key_name.includes("host")
    )?.key_name;
    const urlVal = urlField ? formValues[`${card.category}_${urlField}`] : "";

    if (!secretVal && !urlVal) {
      return {
        label: "Not Configured",
        badgeColor: "bg-slate-800 text-slate-400 border-slate-700",
      };
    }

    return {
      label: "Configured (Untested)",
      badgeColor: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    };
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center space-x-3 mb-1">
            <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2.5">
              <Sliders className="h-6 w-6 text-blue-500" />
              Enterprise Integrations & API Key Vault
            </h1>
            <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 font-bold border border-blue-500/30">
              CONFIGURATION
            </span>
          </div>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            Manage live authentication credentials for AI (Gemini/OpenAI), EDR, XDR, Wazuh SIEM, Threat Intel (VirusTotal/AbuseIPDB), Next-Gen Firewalls, and ITSM. Live connection tests honestly verify whether credentials authenticate with remote services.
          </p>
        </div>

        <button
          onClick={handleSaveAll}
          disabled={saving}
          className="flex items-center justify-center space-x-2 px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-xl shadow-blue-600/30 transition transform hover:-translate-y-0.5 disabled:opacity-50"
        >
          <Save className="h-4 w-4" />
          <span>{saving ? "Saving Configuration..." : "Save All Configurations"}</span>
        </button>
      </div>

      {savedSuccess && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="h-4 w-4" />
          <span>All API keys, endpoints, and credentials have been securely stored in the SOAR database.</span>
        </div>
      )}

      {/* Integration Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {INTEGRATION_SECTIONS.map((section) => {
          const Icon = section.icon;
          const testRes = testResults[section.id];
          const isTesting = testingId === section.id;
          const statusBadge = getCardStatusBadge(section);

          return (
            <div
              key={section.id}
              className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between shadow-lg hover:border-slate-700/80 transition space-y-5"
            >
              {/* Card Header */}
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center space-x-3">
                    <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
                      <Icon className="h-5 w-5 text-blue-400" />
                    </div>
                    <div>
                      <h3 className="font-bold text-base text-white tracking-wide">
                        {section.title}
                      </h3>
                      <span className="text-[10px] font-mono text-slate-500">
                        Category: {section.category}
                      </span>
                    </div>
                  </div>

                  <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${statusBadge.badgeColor}`}>
                    {statusBadge.label}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  {section.description}
                </p>
              </div>

              {/* Fields */}
              <div className="space-y-3.5 bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
                {section.fields.map((field) => {
                  const fieldKey = `${section.category}_${field.key_name}`;
                  const isVisible = visibleSecrets[fieldKey];
                  const value = formValues[fieldKey] || "";

                  return (
                    <div key={field.key_name} className="space-y-1">
                      <label className="text-[11px] font-semibold text-slate-300 block">
                        {field.label}
                      </label>
                      <div className="relative">
                        <input
                          type={field.is_secret && !isVisible ? "password" : "text"}
                          value={value}
                          onChange={(e) => handleChange(section.category, field.key_name, e.target.value)}
                          placeholder={field.placeholder}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                        />
                        {field.is_secret && (
                          <button
                            type="button"
                            onClick={() => toggleSecretVisibility(fieldKey)}
                            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                          >
                            {isVisible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Diagnostic Test Feedback Banner */}
              {testRes && (
                <div
                  className={`p-3 rounded-xl border text-xs animate-in fade-in ${
                    testRes.is_connected && testRes.status === "Connected"
                      ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                      : testRes.status === "Not Configured"
                      ? "bg-slate-800/60 border-slate-700 text-slate-400"
                      : testRes.status === "Unreachable"
                      ? "bg-amber-500/10 border-amber-500/20 text-amber-400"
                      : "bg-rose-500/10 border-rose-500/20 text-rose-400"
                  }`}
                >
                  <div className="flex items-start space-x-2.5">
                    {testRes.is_connected && testRes.status === "Connected" ? (
                      <CheckCircle2 className="h-4 w-4 flex-shrink-0 mt-0.5 text-emerald-400" />
                    ) : testRes.status === "Not Configured" ? (
                      <Sliders className="h-4 w-4 flex-shrink-0 mt-0.5 text-slate-400" />
                    ) : testRes.status === "Unreachable" ? (
                      <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5 text-amber-400" />
                    ) : (
                      <XCircle className="h-4 w-4 flex-shrink-0 mt-0.5 text-rose-400" />
                    )}
                    <div className="space-y-0.5">
                      <div className="font-bold flex items-center gap-2">
                        <span>{testRes.health}</span>
                        {testRes.latency_ms > 0 && (
                          <span className="font-mono text-[10px] opacity-75">
                            ({testRes.latency_ms}ms)
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] opacity-90 leading-tight">
                        {testRes.message}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Card Footer: Test Connection Action */}
              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-3">
                <span className="text-[11px] text-slate-500">
                  {testRes ? "Tested against remote target" : "Verify credential handshake"}
                </span>

                <button
                  type="button"
                  onClick={() => handleTestConnection(section)}
                  disabled={isTesting}
                  className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 text-xs font-semibold transition disabled:opacity-50"
                >
                  <Activity className={`h-3.5 w-3.5 ${isTesting ? "animate-spin text-blue-400" : "text-blue-400"}`} />
                  <span>{isTesting ? "Testing Handshake..." : "Test Connection"}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
