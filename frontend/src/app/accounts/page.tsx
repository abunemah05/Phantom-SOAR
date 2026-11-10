"use client";

import React, { useState, useEffect } from "react";
import { 
  Users, 
  UserPlus, 
  ShieldCheck, 
  KeyRound, 
  Trash2, 
  Power, 
  AlertCircle, 
  CheckCircle2, 
  RefreshCw, 
  Shield, 
  Lock, 
  UserCheck, 
  Clock, 
  X,
  Search,
  BadgeCheck
} from "lucide-react";
import { api } from "@/lib/api";
import { User } from "@/lib/types";
import { getStoredUser, subscribeToAuth } from "@/lib/auth";

export default function AccountsPage() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isAuthorized, setIsAuthorized] = useState<boolean>(true);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>("");
  const [newRole, setNewRole] = useState<string>("Tier 1 Analyst (Triage & Monitoring)");
  const [createLoading, setCreateLoading] = useState<boolean>(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const evaluateAuth = (user: User | null) => {
    setCurrentUser(user);
    if (!user) {
      setIsAuthorized(false);
      return false;
    }
    const roleLower = (user.role || "").toLowerCase();
    const authorized = roleLower.includes("admin") || roleLower.includes("lead");
    setIsAuthorized(authorized);
    return authorized;
  };

  // Load Users
  const loadUsers = async () => {
    try {
      setLoading(true);
      const data = await api.getUsers();
      setUsers(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to load operator accounts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const user = getStoredUser();
    const authorized = evaluateAuth(user);
    if (authorized) {
      loadUsers();
    } else {
      setLoading(false);
    }

    const unsubscribe = subscribeToAuth((updatedUser) => {
      const isAuth = evaluateAuth(updatedUser);
      if (isAuth) {
        loadUsers();
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateLoading(true);
    setModalError(null);

    try {
      await api.createUser({
        username: newUsername.trim(),
        role: newRole,
      });
      setShowCreateModal(false);
      setNewUsername("");
      setNewRole("Tier 1 Analyst (Triage & Monitoring)");
      setSuccessMsg(`Operator account created successfully with default password 'PhantomSOAR1@'.`);
      loadUsers();
    } catch (err: any) {
      setModalError(err.message || "Failed to create user account.");
    } finally {
      setCreateLoading(false);
    }
  };

  const handleResetPassword = async (userId: number, username: string) => {
    if (!confirm(`Are you sure you want to reset the password for '${username}' back to default 'PhantomSOAR1@'? The user will be required to change it on their next login.`)) {
      return;
    }

    try {
      await api.resetUserPassword(userId);
      setSuccessMsg(`Password for '${username}' was reset to 'PhantomSOAR1@'. Operator must change it upon next login.`);
      loadUsers();
    } catch (err: any) {
      setError(err.message || "Failed to reset operator password.");
    }
  };

  const handleFlagCompromised = async (userId: number, username: string) => {
    if (!confirm(`Flag account '${username}' as suspected compromised per NIST SP 800-63B? The user will be required to change their credentials on next authentication.`)) {
      return;
    }

    try {
      await api.flagUserCompromised(userId);
      setSuccessMsg(`Operator '${username}' has been flagged as compromised. Mandatory credential rotation enforced.`);
      loadUsers();
    } catch (err: any) {
      setError(err.message || "Failed to flag account as compromised.");
    }
  };

  const handleToggleActive = async (user: User) => {
    const nextStatus = !user.is_active;
    try {
      await api.updateUser(user.user_id, { is_active: nextStatus });
      setSuccessMsg(`Operator '${user.username}' is now ${nextStatus ? "Enabled" : "Disabled"}.`);
      loadUsers();
    } catch (err: any) {
      setError(err.message || "Failed to update operator status.");
    }
  };

  const handleDeleteUser = async (userId: number, username: string) => {
    if (username === "abunemah") {
      alert("Root administrator account 'abunemah' cannot be removed.");
      return;
    }

    if (!confirm(`Permanently remove operator account '${username}' from Phantom SOAR?`)) {
      return;
    }

    try {
      await api.deleteUser(userId);
      setSuccessMsg(`Operator account '${username}' was permanently deleted.`);
      loadUsers();
    } catch (err: any) {
      setError(err.message || "Failed to delete operator account.");
    }
  };

  // Filter users by search
  const filteredUsers = users.filter((u) => 
    u.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
    u.role.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Statistics
  const totalUsers = users.length;
  const activeCount = users.filter((u) => u.is_active !== false).length;
  const pendingPasswordCount = users.filter((u) => u.must_change_password).length;
  const adminCount = users.filter((u) => u.role.toLowerCase().includes("admin") || u.role.toLowerCase().includes("lead")).length;

  if (!isAuthorized) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] text-center px-4">
        <div className="h-16 w-16 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 mb-4">
          <Lock className="h-8 w-8" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Access Restricted (Admin Only)</h2>
        <p className="text-sm text-slate-400 max-w-md">
          Operator provisioning, password resets, and RBAC governance are restricted exclusively to SOC Administrators. Your current role is <b>{currentUser?.role || "SOC Analyst"}</b>.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-blue-600/10 border border-blue-500/20 text-blue-400">
              <Users className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Operator Accounts & RBAC
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  IAM Security
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Provision SOC analysts, assign role-based access, and oversee the first-login credential lifecycle.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={loadUsers}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs font-semibold text-slate-300 transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-blue-600/20 transition transform hover:-translate-y-0.5"
          >
            <UserPlus className="h-4 w-4" />
            <span>Create New Operator</span>
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="hover:text-rose-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {successMsg && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="hover:text-emerald-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Total Accounts</span>
            <Users className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-white">{totalUsers}</div>
          <span className="text-[11px] text-slate-500 font-medium">Provisioned in system</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Active Operators</span>
            <UserCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400">{activeCount}</div>
          <span className="text-[11px] text-slate-500 font-medium">Authorized to login</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Pending First Login</span>
            <KeyRound className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-400">{pendingPasswordCount}</div>
          <span className="text-[11px] text-slate-500 font-medium">Must update default password</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>SOC Admins / Leads</span>
            <Shield className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black text-purple-400">{adminCount}</div>
          <span className="text-[11px] text-slate-500 font-medium">High privilege accounts</span>
        </div>
      </div>

      {/* Search and Table Container */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        {/* Table Search Toolbar */}
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative w-full sm:w-72">
            <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by username or role..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="text-xs text-slate-400 font-medium">
            Showing {filteredUsers.length} of {totalUsers} accounts
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4">Operator</th>
                <th className="py-3.5 px-4">Assigned Role</th>
                <th className="py-3.5 px-4">Credential Status</th>
                <th className="py-3.5 px-4">Account Status</th>
                <th className="py-3.5 px-4">Provisioned Date</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading && users.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-blue-500" />
                    Loading operator directory...
                  </td>
                </tr>
              ) : filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No operator accounts found matching "{searchQuery}".
                  </td>
                </tr>
              ) : (
                filteredUsers.map((user) => {
                  const isRootAdmin = user.username === "abunemah";
                  const isActive = user.is_active !== false;

                  return (
                    <tr key={user.user_id} className="hover:bg-slate-800/40 transition">
                      {/* Operator column */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center space-x-3">
                          <div className={`h-8 w-8 rounded-lg flex items-center justify-center font-bold text-xs ${
                            isRootAdmin 
                              ? "bg-purple-600/20 text-purple-400 border border-purple-500/30" 
                              : "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                          }`}>
                            {user.username.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-bold text-slate-200 flex items-center gap-1.5">
                              {user.username}
                              {isRootAdmin && (
                                <span className="text-[10px] bg-purple-500/20 text-purple-300 px-1.5 py-0.2 rounded border border-purple-500/30 font-semibold">
                                  Root Admin
                                </span>
                              )}
                            </div>
                            <span className="text-[11px] text-slate-500 font-mono">ID #{user.user_id}</span>
                          </div>
                        </div>
                      </td>

                      {/* Assigned Role */}
                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                          user.role.toLowerCase().includes("admin")
                            ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                            : user.role.toLowerCase().includes("lead")
                            ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                            : user.role.toLowerCase().includes("tier 2")
                            ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                            : user.role.toLowerCase().includes("tier 1")
                            ? "bg-sky-500/10 text-sky-400 border-sky-500/20"
                            : "bg-slate-700/30 text-slate-300 border-slate-600/40"
                        }`}>
                          {user.role}
                        </span>
                      </td>

                      {/* Credential Status */}
                      <td className="py-3.5 px-4">
                        {user.must_change_password ? (
                          <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                            <Clock className="h-3 w-3" />
                            <span>Pending First Login Change</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <BadgeCheck className="h-3 w-3" />
                            <span>Secured & Active</span>
                          </span>
                        )}
                      </td>

                      {/* Account Status */}
                      <td className="py-3.5 px-4">
                        {isActive ? (
                          <span className="inline-flex items-center space-x-1.5 text-emerald-400 font-medium">
                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                            <span>Active</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1.5 text-slate-500 font-medium">
                            <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
                            <span>Disabled</span>
                          </span>
                        )}
                      </td>

                      {/* Provisioned Date */}
                      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                        {user.created_at ? new Date(user.created_at).toLocaleDateString() : "System Init"}
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end space-x-2">
                          {/* Reset Password to Default */}
                          <button
                            onClick={() => handleResetPassword(user.user_id, user.username)}
                            title="Reset password back to default (PhantomSOAR1@)"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-amber-400 transition"
                          >
                            <KeyRound className="h-3.5 w-3.5" />
                          </button>

                          {/* Flag Account as Suspected Compromised (NIST SP 800-63B) */}
                          <button
                            onClick={() => handleFlagCompromised(user.user_id, user.username)}
                            title="Flag as Compromised (Forces reset per NIST SP 800-63B)"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-500/20 text-rose-400 transition"
                          >
                            <Shield className="h-3.5 w-3.5" />
                          </button>

                          {/* Toggle Active / Disabled */}
                          {!isRootAdmin && (
                            <button
                              onClick={() => handleToggleActive(user)}
                              title={isActive ? "Disable operator account" : "Enable operator account"}
                              className={`p-1.5 rounded-lg transition ${
                                isActive 
                                  ? "bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-rose-400" 
                                  : "bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30"
                              }`}
                            >
                              <Power className="h-3.5 w-3.5" />
                            </button>
                          )}

                          {/* Delete Account */}
                          {!isRootAdmin ? (
                            <button
                              onClick={() => handleDeleteUser(user.user_id, user.username)}
                              title="Delete account"
                              className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 transition"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          ) : (
                            <span className="p-1.5 opacity-20 cursor-not-allowed">
                              <ShieldCheck className="h-3.5 w-3.5 text-slate-400" />
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* CREATE OPERATOR MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 relative animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-5">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 rounded-xl bg-blue-600/10 text-blue-400 border border-blue-500/20">
                  <UserPlus className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 text-sm">Provision New Operator</h3>
                  <p className="text-[11px] text-slate-400">Configure credentials and assign RBAC role</p>
                </div>
              </div>
              <button 
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {modalError && (
              <div className="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center space-x-2">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{modalError}</span>
              </div>
            )}

            {/* Informational Policy Box */}
            <div className="mb-5 p-3.5 rounded-xl bg-blue-950/40 border border-blue-500/30 text-xs text-slate-300 space-y-1.5">
              <div className="flex items-center space-x-2 text-blue-400 font-bold">
                <KeyRound className="h-4 w-4" />
                <span>Default Password Policy:</span>
              </div>
              <p className="text-[11px] text-slate-400">
                New accounts are initialized with temporary password: <code className="text-blue-300 font-mono font-bold bg-blue-900/40 px-1 py-0.5 rounded">PhantomSOAR1@</code>
              </p>
              <p className="text-[11px] text-amber-400 font-medium">
                * The operator will be required to change this password immediately upon their first login.
              </p>
            </div>

            {/* Form */}
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300">Operator Username</label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. analyst_sarah, lead_ahmed..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-medium"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300">RBAC Role Assignment</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-medium"
                >
                  <option value="Tier 1 Analyst (Triage & Monitoring)">Tier 1 Analyst (Triage & Monitoring)</option>
                  <option value="Tier 2 Analyst (Senior Responder)">Tier 2 Analyst (Senior Responder)</option>
                  <option value="SOC Lead / Incident Commander">SOC Lead / Incident Commander</option>
                  <option value="Threat Hunter / Intel Specialist">Threat Hunter / Intel Specialist</option>
                  <option value="SOC Auditor (Read-Only)">SOC Auditor (Read-Only)</option>
                  <option value="Lead SOC Architect / Admin">Lead SOC Architect / Admin</option>
                </select>
              </div>

              <div className="pt-3 flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createLoading}
                  className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/20 transition disabled:opacity-50 flex items-center space-x-2"
                >
                  {createLoading && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                  <span>{createLoading ? "Creating Operator..." : "Provision Account"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
