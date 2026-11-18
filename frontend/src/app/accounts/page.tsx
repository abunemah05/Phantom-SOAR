"use client";

import React, { useCallback, useMemo, useRef, useState } from "react";
import {
  Bot,
  KeyRound,
  Loader2,

  Plus,
  Power,
  RefreshCw,
  RotateCw,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  Trash2,
  UserCheck,
  UserPlus,
  Users,
} from "lucide-react";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { formatDate, formatDateTime } from "@/lib/format";
import { ASSIGNABLE_ROLES, ROLE_SOC_ANALYST, canAdminister, isAdmin, roleLevel } from "@/lib/roles";
import { IngestTokenInfo, User } from "@/lib/types";
import { useResource } from "@/hooks/useResource";
import { useAuth } from "@/components/AuthGate";
import { useConfirm } from "@/components/ConfirmDialog";
import Dialog from "@/components/Dialog";
import SecretOnceDialog, { OneTimeSecret } from "@/components/SecretOnceDialog";
import { AccessDenied, EmptyState, ErrorState, InlineNotice, LoadingState, StaleBanner } from "@/components/StateViews";
import { useToast } from "@/components/Toast";

const INPUT =
  "w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500";
const ICON_BTN =
  "p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:opacity-30 disabled:cursor-not-allowed";

/** "10.0.0.5, 192.168.1.0/24" or one entry per line -> trimmed list. The backend validates each entry. */
function parseAllowlist(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseDays(text: string): { value?: number; error?: string } {
  if (!text.trim()) return {};
  if (!/^\d+$/.test(text.trim()) || Number(text) < 1 || Number(text) > 3650) {
    return { error: "Expiry must be a whole number of days between 1 and 3650." };
  }
  return { value: Number(text) };
}

export default function AccountsPage() {
  const { user: me } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const allowed = canAdminister(me);

  const usersFetcher = useCallback(() => api.getUsers(), []);
  const users = useResource(usersFetcher, { enabled: allowed });
  const tokensFetcher = useCallback(() => api.getIngestTokens(), []);
  const tokens = useResource(tokensFetcher, { enabled: allowed });

  const [search, setSearch] = useState("");
  const [secret, setSecret] = useState<OneTimeSecret | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showService, setShowService] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [policyFor, setPolicyFor] = useState<User | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  const list = useMemo(() => users.data ?? [], [users.data]);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return list;
    return list.filter((u) => u.username.toLowerCase().includes(q) || u.role.toLowerCase().includes(q));
  }, [list, search]);

  if (!allowed) {
    return (
      <AccessDenied title="Access restricted (administrators only)">
        Operator provisioning, password resets and service accounts are limited to administrators. Your role is{" "}
        <b>{me?.role || "unknown"}</b>.
      </AccessDenied>
    );
  }

  const run = async (target: User, fn: () => Promise<void>, failure: string) => {
    setBusyId(target.user_id);
    try {
      await fn();
    } catch (err) {
      toast.error(describeError(err, failure));
    } finally {
      setBusyId(null);
    }
  };

  const resetPassword = async (target: User) => {
    const ok = await confirm({
      title: `Reset the password for ${target.username}?`,
      message: "The current password stops working and every active session for this account is signed out.",
      items: ["A one-time password is shown once, to you.", "The operator must choose a new password at the next sign-in."],
      confirmLabel: "Reset password",
      tone: "warning",
    });
    if (!ok) return;
    await run(target, async () => {
      const res = await api.resetUserPassword(target.user_id);
      if (res.temporary_password) {
        setSecret({
          title: `One-time password for ${target.username}`,
          value: res.temporary_password,
          note: "Shown once. Share it over a trusted channel. The operator must change it at first sign-in.",
        });
      } else {
        toast.success(res.message || `Password for ${target.username} was reset.`);
      }
      void users.reload();
    }, "Could not reset the password.");
  };

  const flagCompromised = async (target: User) => {
    const ok = await confirm({
      title: `Flag ${target.username} as compromised?`,
      message: "This account is treated as breached (NIST SP 800-63B).",
      items: ["Its sessions are revoked.", "A new password is required at the next authentication."],
      confirmLabel: "Flag as compromised",
      tone: "danger",
    });
    if (!ok) return;
    await run(target, async () => {
      await api.flagUserCompromised(target.user_id);
      toast.success(`${target.username} was flagged as compromised; credential rotation is now mandatory.`);
      void users.reload();
    }, "Could not flag the account.");
  };

  const toggleActive = async (target: User) => {
    const enable = target.is_active === false;
    const ok = await confirm({
      title: enable ? `Enable ${target.username}?` : `Disable ${target.username}?`,
      message: enable
        ? "The account can sign in (or authenticate with its API key) again."
        : "The account is signed out and cannot authenticate until it is enabled again. Its history is kept.",
      confirmLabel: enable ? "Enable account" : "Disable account",
      tone: enable ? "default" : "warning",
    });
    if (!ok) return;
    await run(target, async () => {
      await api.updateUser(target.user_id, { is_active: enable });
      toast.success(`${target.username} is now ${enable ? "enabled" : "disabled"}.`);
      void users.reload();
    }, "Could not change the account status.");
  };

  const removeUser = async (target: User) => {
    const ok = await confirm({
      title: `Permanently delete ${target.username}?`,
      message: "The account is removed and cannot sign in or use its API key again. This cannot be undone.",
      items: ["Audit-log entries written by this account are kept."],
      confirmLabel: "Delete account",
      tone: "danger",
      requireText: target.username,
    });
    if (!ok) return;
    await run(target, async () => {
      await api.deleteUser(target.user_id);
      toast.success(`${target.username} was deleted.`);
      void users.reload();
    }, "Could not delete the account.");
  };

  const rotateKey = async (target: User) => {
    const ok = await confirm({
      title: `Rotate the API key of ${target.username}?`,
      message: "A new key is issued and the current key stops working immediately.",
      items: ["Any agent still using the old key will get 401 until it is updated.", "The new key is shown once."],
      confirmLabel: "Rotate key",
      tone: "danger",
    });
    if (!ok) return;
    await run(target, async () => {
      const res = await api.rotateServiceAccountKey(target.user_id);
      setSecret({
        title: `API key for ${res.username || target.username}`,
        value: res.api_key,
        note: "Shown once; only a digest is stored. Send it as the X-Phantom-Agent-Key header. The previous key no longer works.",
      });
      void users.reload();
    }, "Could not rotate the API key.");
  };

  const revokeToken = async (token: IngestTokenInfo) => {
    const ok = await confirm({
      title: `Revoke ingest token "${token.name}"?`,
      message: "Senders that use this token are rejected immediately. A revoked token cannot be restored.",
      confirmLabel: "Revoke token",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await api.revokeIngestToken(token.id);
      toast.success(`Ingest token "${token.name}" was revoked.`);
      void tokens.reload();
    } catch (err) {
      toast.error(describeError(err, "Could not revoke the token."));
    }
  };

  const totalUsers = list.length;
  const activeCount = list.filter((u) => u.is_active !== false).length;
  const pendingPassword = list.filter((u) => u.must_change_password && !u.is_service_account).length;
  const adminCount = list.filter((u) => isAdmin(u)).length;
  const serviceCount = list.filter((u) => u.is_service_account).length;

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-blue-600/10 border border-blue-500/20 text-blue-400">
            <Users className="h-6 w-6" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Operator accounts &amp; RBAC</h1>
            <p className="text-xs text-slate-400 mt-0.5">Provision operators and AI agent accounts, assign roles and manage credentials.</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => { void users.reload(); void tokens.reload(); }} className="flex items-center gap-1.5 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs font-semibold text-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
            <RefreshCw className={`h-3.5 w-3.5 ${users.loading ? "animate-spin" : ""}`} aria-hidden="true" /> Refresh
          </button>
          <button type="button" onClick={() => setShowService(true)} title="Non-human account whose API key lets an AI triage agent use the agent API" className="flex items-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 text-cyan-300 rounded-xl text-xs font-bold focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400">
            <Bot className="h-4 w-4" aria-hidden="true" /> Create AI agent account
          </button>
          <button type="button" onClick={() => setShowCreate(true)} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300">
            <UserPlus className="h-4 w-4" aria-hidden="true" /> Create operator
          </button>
        </div>
      </div>

      {users.error && !users.data ? (
        <ErrorState title="Could not load accounts" message={users.error} onRetry={() => void users.reload()} />
      ) : users.loading && !users.data ? (
        <LoadingState label="Loading operator directory..." />
      ) : (
        <>
          {users.error && <StaleBanner message={users.error} onRetry={() => void users.reload()} />}
          <section aria-label="Account totals" className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Stat label="Total accounts" value={totalUsers} icon={<Users className="h-4 w-4 text-blue-400" aria-hidden="true" />} sub={`${serviceCount} service account${serviceCount === 1 ? "" : "s"}`} />
            <Stat label="Active" value={activeCount} tone="text-emerald-400" icon={<UserCheck className="h-4 w-4 text-emerald-400" aria-hidden="true" />} sub="Allowed to authenticate" />
            <Stat label="Pending first login" value={pendingPassword} tone="text-amber-400" icon={<KeyRound className="h-4 w-4 text-amber-400" aria-hidden="true" />} sub="Must change password" />
            <Stat label="Administrators" value={adminCount} tone="text-purple-400" icon={<Shield className="h-4 w-4 text-purple-400" aria-hidden="true" />} sub="High-privilege accounts" />
          </section>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="relative w-full sm:w-72">
                <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
                <label htmlFor="user-search" className="sr-only">Search accounts</label>
                <input id="user-search" type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search by username or role..." className={`${INPUT} pl-9`} />
              </div>
              <div className="text-xs text-slate-400 font-medium" aria-live="polite">Showing {filtered.length} of {totalUsers} accounts</div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <caption className="sr-only">Operator and service accounts</caption>
                <thead className="bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th scope="col" className="py-3.5 px-4">Account</th>
                    <th scope="col" className="py-3.5 px-4">Role</th>
                    <th scope="col" className="py-3.5 px-4">Credentials</th>
                    <th scope="col" className="py-3.5 px-4">Status</th>
                    <th scope="col" className="py-3.5 px-4">Created</th>
                    <th scope="col" className="py-3.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={6}>
                        <EmptyState icon={Users} title={search ? `No accounts match "${search}"` : "No accounts yet"} />
                      </td>
                    </tr>
                  ) : (
                    filtered.map((u) => (
                      <UserRow
                        key={u.user_id}
                        user={u}
                        isSelf={u.user_id === me?.user_id}
                        busy={busyId === u.user_id}
                        onReset={() => void resetPassword(u)}
                        onFlag={() => void flagCompromised(u)}
                        onToggle={() => void toggleActive(u)}
                        onDelete={() => void removeUser(u)}
                        onRotate={() => void rotateKey(u)}
                        onPolicy={() => setPolicyFor(u)}
                      />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* Webhook ingest tokens */}
      <section aria-labelledby="tokens-heading" className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between gap-3">
          <div>
            <h2 id="tokens-heading" className="text-sm font-bold text-slate-100">Webhook ingest tokens</h2>
            <p className="text-[11px] text-slate-500 mt-0.5">Credentials for Wazuh or other senders posting alerts to the ingest webhook. A token is shown once, when created.</p>
          </div>
          <button type="button" onClick={() => setShowToken(true)} className="flex items-center gap-1.5 px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300">
            <Plus className="h-3.5 w-3.5" aria-hidden="true" /> New token
          </button>
        </div>
        {tokens.error && !tokens.data ? (
          <div className="p-4"><ErrorState compact title="Could not load ingest tokens" message={tokens.error} onRetry={() => void tokens.reload()} /></div>
        ) : tokens.loading && !tokens.data ? (
          <LoadingState label="Loading ingest tokens..." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <caption className="sr-only">Webhook ingest tokens</caption>
              <thead className="bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th scope="col" className="py-3 px-4">Name</th>
                  <th scope="col" className="py-3 px-4">Token</th>
                  <th scope="col" className="py-3 px-4">Status</th>
                  <th scope="col" className="py-3 px-4">Expires</th>
                  <th scope="col" className="py-3 px-4">Last used</th>
                  <th scope="col" className="py-3 px-4 text-right"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {(tokens.data ?? []).length === 0 ? (
                  <tr><td colSpan={6}><EmptyState icon={KeyRound} title="No ingest tokens">The webhook falls back to the shared secret from the environment, if one is set.</EmptyState></td></tr>
                ) : (
                  (tokens.data ?? []).map((t) => (
                    <tr key={t.id} className="hover:bg-slate-800/40">
                      <td className="py-3 px-4 font-semibold text-slate-200">{t.name}</td>
                      <td className="py-3 px-4 font-mono text-slate-400">{t.token_prefix}…</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold border ${t.status === "active" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-slate-700/30 text-slate-400 border-slate-600/40"}`}>{t.status}</span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">{t.expires_at ? formatDate(t.expires_at) : "never"}</td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">{t.last_used_at ? formatDateTime(t.last_used_at) : "never"}</td>
                      <td className="py-3 px-4 text-right">
                        {t.status === "active" && (
                          <button type="button" onClick={() => void revokeToken(t)} className="px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-600 text-rose-300 hover:text-white border border-rose-500/30 text-[11px] font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400">
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <CreateOperatorDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(created) => {
          setShowCreate(false);
          void users.reload();
          if (created.temporary_password) {
            setSecret({
              title: `One-time password for ${created.username}`,
              value: created.temporary_password,
              note: "Shown once. Share it over a trusted channel. The operator must change it at first sign-in.",
            });
          } else {
            toast.success(`Operator ${created.username} was created.`);
          }
        }}
      />
      <CreateServiceDialog
        open={showService}
        onClose={() => setShowService(false)}
        onCreated={(res) => {
          setShowService(false);
          void users.reload();
          setSecret({
            title: `API key for ${res.username}`,
            value: res.api_key,
            note: "Shown once; only a digest is stored. The agent sends it as the X-Phantom-Agent-Key header.",
          });
        }}
      />
      <PolicyDialog
        target={policyFor}
        onClose={() => setPolicyFor(null)}
        onSaved={(name) => {
          setPolicyFor(null);
          void users.reload();
          toast.success(`Access policy for ${name} was updated.`);
        }}
      />
      <CreateTokenDialog
        open={showToken}
        onClose={() => setShowToken(false)}
        onCreated={(res) => {
          setShowToken(false);
          void tokens.reload();
          setSecret({
            title: `Ingest token "${res.name}"`,
            value: res.token,
            note: "Shown once. Configure it as the webhook credential in the sender.",
          });
        }}
      />
      <SecretOnceDialog secret={secret} onDone={() => setSecret(null)} />
    </div>
  );
}

function Stat({ label, value, sub, icon, tone = "text-white" }: { label: string; value: number; sub: string; icon: React.ReactNode; tone?: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center justify-between text-slate-400 text-xs mb-1"><span>{label}</span>{icon}</div>
      <div className={`text-2xl font-black ${tone}`}>{value}</div>
      <span className="text-[11px] text-slate-500 font-medium">{sub}</span>
    </div>
  );
}

function UserRow({
  user, isSelf, busy, onReset, onFlag, onToggle, onDelete, onRotate, onPolicy,
}: {
  user: User;
  isSelf: boolean;
  busy: boolean;
  onReset: () => void;
  onFlag: () => void;
  onToggle: () => void;
  onDelete: () => void;
  onRotate: () => void;
  onPolicy: () => void;
}) {
  const isBootstrap = Boolean(user.is_bootstrap_admin);
  const isActive = user.is_active !== false;
  const isService = Boolean(user.is_service_account);
  const level = roleLevel(user);
  const protectedReason = isBootstrap ? "The bootstrap administrator cannot be changed this way" : isSelf ? "You cannot do this to your own account" : "";
  const roleClass =
    level === "admin" ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
    : level === "security_engineer" ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
    : level === "analyst" ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
    : level === "service" ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
    : "bg-slate-700/30 text-slate-300 border-slate-600/40";

  return (
    <tr className="hover:bg-slate-800/40 transition">
      <td className="py-3.5 px-4">
        <div className="flex items-center gap-3">
          <div aria-hidden="true" className={`h-8 w-8 rounded-lg flex items-center justify-center font-bold text-xs ${isBootstrap ? "bg-purple-600/20 text-purple-400 border border-purple-500/30" : "bg-blue-600/20 text-blue-400 border border-blue-500/30"}`}>
            {user.username.charAt(0).toUpperCase()}
          </div>
          <div>
            <div className="font-bold text-slate-200 flex flex-wrap items-center gap-1.5">
              {user.username}
              {isSelf && <span className="text-[10px] bg-slate-700/60 text-slate-300 px-1.5 rounded border border-slate-600/50 font-semibold">you</span>}
              {isBootstrap && <span className="text-[10px] bg-purple-500/20 text-purple-300 px-1.5 rounded border border-purple-500/30 font-semibold">Bootstrap admin</span>}
              {isService && (
                <span className="inline-flex items-center gap-1 text-[10px] bg-cyan-500/15 text-cyan-300 px-1.5 rounded border border-cyan-500/30 font-semibold" title="Non-human account for the agent API. Authenticates with an API key and cannot sign in to the console.">
                  <Bot className="h-3 w-3" aria-hidden="true" /> Service account
                </span>
              )}
            </div>
            <span className="text-[11px] text-slate-500 font-mono">ID #{user.user_id}</span>
          </div>
        </div>
      </td>
      <td className="py-3.5 px-4"><span className={`inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold border ${roleClass}`}>{user.role}</span></td>
      <td className="py-3.5 px-4 space-y-1">
        {isService ? (
          <>
            <div className="text-cyan-300 font-semibold">API key{user.api_key_prefix ? ` ${user.api_key_prefix}…` : ""}</div>
            <div className="text-[11px] text-slate-500">
              {user.expires_at ? `expires ${formatDate(user.expires_at)}` : "no expiry"}
              {user.ip_allowlist && user.ip_allowlist.length > 0 ? ` · ${user.ip_allowlist.length} allowed source${user.ip_allowlist.length === 1 ? "" : "s"}` : " · any source IP"}
            </div>
            {user.last_used_at && <div className="text-[11px] text-slate-500">last used {formatDateTime(user.last_used_at)}{user.last_used_ip ? ` from ${user.last_used_ip}` : ""}</div>}
          </>
        ) : (
          <>
            {user.must_change_password ? (
              <span className="inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">Password change pending</span>
            ) : (
              <span className="inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Password set</span>
            )}
            <div className="text-[11px] text-slate-500">{user.mfa_enabled ? "MFA on" : "MFA off"}{user.compromised_reset_required ? " · flagged compromised" : ""}</div>
          </>
        )}
      </td>
      <td className="py-3.5 px-4">
        <span className={`inline-flex items-center gap-1.5 font-medium ${isActive ? "text-emerald-400" : "text-slate-500"}`}>
          <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${isActive ? "bg-emerald-400" : "bg-slate-500"}`} />
          {isActive ? "Active" : "Disabled"}
        </span>
      </td>
      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">{formatDate(user.created_at, "System init")}</td>
      <td className="py-3.5 px-4 text-right">
        <div className="flex items-center justify-end gap-1.5">
          {busy && <Loader2 className="h-3.5 w-3.5 animate-spin text-slate-400" aria-label="Working" />}
          {isService ? (
            <>
              <button type="button" disabled={busy} onClick={onPolicy} title="Edit expiry and allowed source IPs" aria-label={`Edit access policy of ${user.username}`} className={`${ICON_BTN} text-cyan-300`}>
                <Settings2 className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
              <button type="button" disabled={busy} onClick={onRotate} title="Rotate API key (the current key stops working immediately)" aria-label={`Rotate API key of ${user.username}`} className={`${ICON_BTN} text-cyan-300`}>
                <RotateCw className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </>
          ) : (
            <>
              <button type="button" disabled={busy} onClick={onReset} title="Reset password" aria-label={`Reset password of ${user.username}`} className={`${ICON_BTN} text-amber-400`}>
                <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
              <button type="button" disabled={busy || isSelf} onClick={onFlag} title={isSelf ? protectedReason : "Flag as compromised (forces credential rotation)"} aria-label={`Flag ${user.username} as compromised`} className={`${ICON_BTN} text-rose-400`}>
                <Shield className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </>
          )}
          <button type="button" disabled={busy || isBootstrap || isSelf} onClick={onToggle} title={isBootstrap || isSelf ? protectedReason : isActive ? "Disable account" : "Enable account"} aria-label={`${isActive ? "Disable" : "Enable"} ${user.username}`} className={`${ICON_BTN} ${isActive ? "text-slate-400" : "text-emerald-400"}`}>
            <Power className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
          {isBootstrap ? (
            <span className="p-1.5 opacity-40" title="The bootstrap administrator cannot be deleted"><ShieldCheck className="h-3.5 w-3.5 text-slate-400" aria-label="Bootstrap administrator cannot be deleted" /></span>
          ) : (
            <button type="button" disabled={busy || isSelf} onClick={onDelete} title={isSelf ? protectedReason : "Delete account"} aria-label={`Delete ${user.username}`} className={`${ICON_BTN} text-slate-400 hover:text-rose-400`}>
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
      </td>
    </tr>
  );
}

function CreateOperatorDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (u: User & { temporary_password?: string }) => void }) {
  const [username, setUsername] = useState("");
  const [role, setRole] = useState(ROLE_SOC_ANALYST);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const firstRef = useRef<HTMLInputElement>(null);

  const close = () => { setError(null); setUsername(""); setRole(ROLE_SOC_ANALYST); onClose(); };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await api.createUser({ username: username.trim(), role });
      setUsername("");
      setRole(ROLE_SOC_ANALYST);
      onCreated(created);
    } catch (err) {
      setError(describeError(err, "Could not create the account."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title="Create operator" description="The server issues a one-time password; the operator must change it at first sign-in." size="sm" initialFocusRef={firstRef}>
      <form onSubmit={submit} className="space-y-4">
        {error && <InlineNotice tone="error">{error}</InlineNotice>}
        <div className="space-y-1.5">
          <label htmlFor="new-username" className="text-xs font-semibold text-slate-300">Username</label>
          <input ref={firstRef} id="new-username" required value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" placeholder="e.g. analyst_sarah" className={INPUT} />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="new-role" className="text-xs font-semibold text-slate-300">Role</label>
          <select id="new-role" value={role} onChange={(e) => setRole(e.target.value)} className={INPUT}>
            {ASSIGNABLE_ROLES.map((r) => <option key={r.role} value={r.role}>{r.role}</option>)}
          </select>
          <p className="text-[11px] text-slate-500">{ASSIGNABLE_ROLES.find((r) => r.role === role)?.description}</p>
        </div>
        <FormButtons busy={busy} onCancel={close} submitLabel="Create operator" disabled={!username.trim()} />
      </form>
    </Dialog>
  );
}

function CreateServiceDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (res: { username: string; api_key: string }) => void }) {
  const [username, setUsername] = useState("");
  const [days, setDays] = useState("90");
  const [ips, setIps] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const firstRef = useRef<HTMLInputElement>(null);

  const close = () => { setError(null); onClose(); };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const parsed = parseDays(days);
    if (parsed.error) { setError(parsed.error); return; }
    setBusy(true);
    try {
      const allow = parseAllowlist(ips);
      const res = await api.createServiceAccount({
        username: username.trim(),
        ...(parsed.value !== undefined ? { expires_in_days: parsed.value } : {}),
        ...(allow.length ? { ip_allowlist: allow } : {}),
      });
      setUsername("");
      setIps("");
      onCreated(res);
    } catch (err) {
      setError(describeError(err, "Could not create the service account."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title="Create AI agent account" description="A non-human account that authenticates with an API key and may only use the agent API. It cannot sign in to this console." size="sm" initialFocusRef={firstRef} icon={<Bot className="h-5 w-5 text-cyan-300 mt-0.5" aria-hidden="true" />}>
      <form onSubmit={submit} className="space-y-4">
        {error && <InlineNotice tone="error">{error}</InlineNotice>}
        <div className="space-y-1.5">
          <label htmlFor="svc-username" className="text-xs font-semibold text-slate-300">Account name</label>
          <input ref={firstRef} id="svc-username" required value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" placeholder="e.g. triage-agent" className={INPUT} />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="svc-days" className="text-xs font-semibold text-slate-300">Key expires after (days)</label>
          <input id="svc-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} placeholder="blank = backend default" className={INPUT} />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="svc-ips" className="text-xs font-semibold text-slate-300">Allowed source IPs / CIDRs (optional)</label>
          <textarea id="svc-ips" rows={2} value={ips} onChange={(e) => setIps(e.target.value)} placeholder="10.0.0.5, 192.168.10.0/24" className={`${INPUT} font-mono`} />
          <p className="text-[11px] text-slate-500">Separate entries with commas, spaces or new lines. Empty allows any source.</p>
        </div>
        <FormButtons busy={busy} onCancel={close} submitLabel="Create account and key" disabled={!username.trim()} />
      </form>
    </Dialog>
  );
}

function PolicyDialog({ target, onClose, onSaved }: { target: User | null; onClose: () => void; onSaved: (name: string) => void }) {
  return (
    <Dialog open={target !== null} onClose={onClose} title={target ? `Access policy for ${target.username}` : ""} description="Changes apply to the existing key; it is not rotated." size="sm">
      {target && <PolicyForm key={target.user_id} target={target} onClose={onClose} onSaved={onSaved} />}
    </Dialog>
  );
}

function PolicyForm({ target, onClose, onSaved }: { target: User; onClose: () => void; onSaved: (name: string) => void }) {
  const [days, setDays] = useState("");
  const [clearExpiry, setClearExpiry] = useState(false);
  const [ips, setIps] = useState((target.ip_allowlist ?? []).join("\n"));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = useConfirm();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const parsed = parseDays(days);
    if (parsed.error) { setError(parsed.error); return; }
    const allow = parseAllowlist(ips);
    const ok = await confirm({
      title: `Update the access policy of ${target.username}?`,
      message: "The key is checked against the new rules from the next request.",
      items: [
        clearExpiry ? "The key will no longer expire." : parsed.value !== undefined ? `The key will expire in ${parsed.value} days from now.` : "The expiry is unchanged.",
        allow.length ? `Requests are accepted only from: ${allow.join(", ")}.` : "Any source IP will be accepted.",
      ],
      confirmLabel: "Save policy",
      tone: "warning",
    });
    if (!ok) return;
    setBusy(true);
    try {
      await api.updateServiceAccountPolicy(target.user_id, {
        ...(clearExpiry ? { clear_expiry: true } : parsed.value !== undefined ? { expires_in_days: parsed.value } : {}),
        ip_allowlist: allow,
      });
      onSaved(target.username);
    } catch (err) {
      setError(describeError(err, "Could not update the policy."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      {error && <InlineNotice tone="error">{error}</InlineNotice>}
      <p className="text-[11px] text-slate-500">
        Currently: {target.expires_at ? `expires ${formatDate(target.expires_at)}` : "no expiry"}.
      </p>
      <div className="space-y-1.5">
        <label htmlFor="pol-days" className="text-xs font-semibold text-slate-300">New expiry, days from now</label>
        <input id="pol-days" inputMode="numeric" value={days} disabled={clearExpiry} onChange={(e) => setDays(e.target.value)} placeholder="leave blank to keep" className={INPUT} />
        <label className="flex items-center gap-2 text-[11px] text-slate-400">
          <input type="checkbox" checked={clearExpiry} onChange={(e) => setClearExpiry(e.target.checked)} /> Remove the expiry
        </label>
      </div>
      <div className="space-y-1.5">
        <label htmlFor="pol-ips" className="text-xs font-semibold text-slate-300">Allowed source IPs / CIDRs</label>
        <textarea id="pol-ips" rows={3} value={ips} onChange={(e) => setIps(e.target.value)} className={`${INPUT} font-mono`} />
        <p className="text-[11px] text-slate-500">Empty removes the restriction.</p>
      </div>
      <FormButtons busy={busy} onCancel={onClose} submitLabel="Save policy" />
    </form>
  );
}

function CreateTokenDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (t: { name: string; token: string }) => void }) {
  const [name, setName] = useState("");
  const [days, setDays] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const firstRef = useRef<HTMLInputElement>(null);

  const close = () => { setError(null); onClose(); };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const parsed = parseDays(days);
    if (parsed.error) { setError(parsed.error); return; }
    setBusy(true);
    try {
      const res = await api.createIngestToken({ name: name.trim(), ...(parsed.value !== undefined ? { expires_in_days: parsed.value } : {}) });
      setName("");
      setDays("");
      onCreated(res);
    } catch (err) {
      setError(describeError(err, "Could not create the token."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title="New webhook ingest token" description="Name it after the sender so it can be revoked on its own." size="sm" initialFocusRef={firstRef}>
      <form onSubmit={submit} className="space-y-4">
        {error && <InlineNotice tone="error">{error}</InlineNotice>}
        <div className="space-y-1.5">
          <label htmlFor="tok-name" className="text-xs font-semibold text-slate-300">Name</label>
          <input ref={firstRef} id="tok-name" required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. wazuh-manager-prod" className={INPUT} />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="tok-days" className="text-xs font-semibold text-slate-300">Expires after (days, optional)</label>
          <input id="tok-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} className={INPUT} />
        </div>
        <FormButtons busy={busy} onCancel={close} submitLabel="Create token" disabled={!name.trim()} />
      </form>
    </Dialog>
  );
}

function FormButtons({ busy, onCancel, submitLabel, disabled }: { busy: boolean; onCancel: () => void; submitLabel: string; disabled?: boolean }) {
  return (
    <div className="flex justify-end gap-2 pt-2">
      <button type="button" onClick={onCancel} className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">Cancel</button>
      <button type="submit" disabled={busy || disabled} className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300">
        {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
        {submitLabel}
      </button>
    </div>
  );
}

