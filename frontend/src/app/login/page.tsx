"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { 
  Shield, 
  Lock, 
  User, 
  Eye, 
  EyeOff, 
  LogIn, 
  AlertCircle, 
  CheckCircle2, 
  Radio, 
  KeyRound,
  ShieldCheck,
  Smartphone
} from "lucide-react";
import { api } from "@/lib/api";
import { getStoredUser, setStoredAuth, clearAuth } from "@/lib/auth";
import { needsPasswordChange } from "@/lib/roles";
import { User as UserType } from "@/lib/types";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [mfaCode, setMfaCode] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);
  const [currentLoggedInUser, setCurrentLoggedInUser] = useState<UserType | null>(null);

  // MFA Challenge State
  const [mfaRequired, setMfaRequired] = useState<boolean>(false);

  // Mandatory First Login / Compromised Password Change State
  const [requiresPasswordChange, setRequiresPasswordChange] = useState<boolean>(false);
  const [changeUsername, setChangeUsername] = useState<string>("");
  const [currentPassword, setCurrentPassword] = useState<string>("");
  const [newPassword, setNewPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [changeLoading, setChangeLoading] = useState<boolean>(false);
  const [changeError, setChangeError] = useState<string | null>(null);
  const [changeNotice, setChangeNotice] = useState<string | null>(null);
  // True when we arrived here with a pending password change and do not know the current password.
  const [askCurrentPassword, setAskCurrentPassword] = useState<boolean>(false);
  const [changeMfaEnabled, setChangeMfaEnabled] = useState<boolean>(false);
  const [changeMfaCode, setChangeMfaCode] = useState<string>("");

  useEffect(() => {
    const user = getStoredUser();
    if (user) {
      if (needsPasswordChange(user)) {
        setChangeUsername(user.username);
        setChangeMfaEnabled(Boolean(user.mfa_enabled));
        setAskCurrentPassword(true);
        setRequiresPasswordChange(true);
      } else {
        setCurrentLoggedInUser(user);
      }
    }
  }, []);

  const signOut = async () => {
    await api.logout();
    setCurrentLoggedInUser(null);
    setRequiresPasswordChange(false);
    setAskCurrentPassword(false);
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setPassword("");
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setChangeNotice(null);

    try {
      const res = await api.login(username.trim(), password, mfaRequired ? mfaCode.trim() : undefined);
      
      // If user has MFA enabled and hasn't supplied a code yet
      if (res && res.mfa_required) {
        setMfaRequired(true);
        setLoading(false);
        return;
      }

      if (res && res.user && res.access_token) {
        setStoredAuth(res.user, res.access_token);
        setCurrentLoggedInUser(res.user);

        if (needsPasswordChange(res.user)) {
          setChangeUsername(res.user.username);
          setCurrentPassword(password);
          setAskCurrentPassword(false);
          setRequiresPasswordChange(true);
        } else {
          setSuccess(true);
          setTimeout(() => {
            router.push("/");
          }, 400);
        }
      }
    } catch (err: any) {
      setError(err.message || "Authentication failed. Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChangeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setChangeLoading(true);
    setChangeError(null);

    if (newPassword !== confirmPassword) {
      setChangeError("New password and confirmation passphrase do not match.");
      setChangeLoading(false);
      return;
    }

    // NIST length recommendations
    if (newPassword.length < 15) {
      setChangeError("NIST SP 800-63B standard requires a minimum length of 15 characters for single-factor accounts. Passphrases are highly recommended.");
      setChangeLoading(false);
      return;
    }

    try {
      const res = await api.changePassword({
        username: changeUsername,
        current_password: currentPassword,
        new_password: newPassword,
        ...(changeMfaCode.trim() ? { mfa_code: changeMfaCode.trim() } : {}),
      });

      setRequiresPasswordChange(false);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");

      // The backend invalidates earlier sessions on a password change and returns a new one.
      if (res?.access_token && res.user && !needsPasswordChange(res.user)) {
        setStoredAuth(res.user, res.access_token);
        setSuccess(true);
        setTimeout(() => {
          router.push("/");
        }, 500);
      } else {
        clearAuth();
        setCurrentLoggedInUser(null);
        setUsername(changeUsername);
        setPassword("");
        setChangeNotice("Password updated. Sign in again with your new password.");
      }
    } catch (err: any) {
      setChangeError(err.message || "Failed to update password. Please check security policy requirements.");
    } finally {
      setChangeLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center px-4 sm:px-6 lg:px-8 relative overflow-hidden font-sans">
      {/* Background Cyber Grid Accent */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-25 pointer-events-none" />
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main Authentication Card */}
      <div className="w-full max-w-md z-10">
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center h-14 w-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 shadow-xl shadow-blue-500/25 mb-3 border border-blue-400/30">
            <Shield className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-black tracking-wider text-white flex items-center justify-center space-x-2">
            <span>PHANTOM</span>
            <span className="text-sm px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-extrabold border border-blue-500/30">
              SOAR
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-medium tracking-wide mt-1">
            Enterprise Security Orchestration, Automation, & Response
          </p>
        </div>

        {/* Card Box */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl shadow-2xl p-7 backdrop-blur-xl">
          {/* Mandatory Password Change Step */}
          {requiresPasswordChange ? (
            <div>
              <div className="mb-5 text-center">
                <div className="inline-flex p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20 mb-2">
                  <KeyRound className="h-5 w-5" />
                </div>
                <h2 className="text-base font-bold text-white">NIST Password Policy Update</h2>
                <p className="text-xs text-slate-400 mt-1">
                  NIST SP 800-63B requires a minimum of 15 characters for single-factor accounts. Paste from password managers is fully supported.
                </p>
              </div>

              {changeError && (
                <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-start space-x-2 text-rose-400 text-xs">
                  <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                  <span>{changeError}</span>
                </div>
              )}

              <form onSubmit={handlePasswordChangeSubmit} className="space-y-4">
                <div className="text-[11px] text-slate-400">
                  Account: <b className="text-slate-200">{changeUsername}</b>
                </div>
                {askCurrentPassword && (
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Current (Temporary) Password
                    </label>
                    <input
                      type="password"
                      required
                      autoComplete="current-password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      placeholder="Password you signed in with"
                      className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                    />
                  </div>
                )}
                {askCurrentPassword && changeMfaEnabled && (
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Authenticator Code (needed if your session has expired)
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      value={changeMfaCode}
                      onChange={(e) => setChangeMfaCode(e.target.value)}
                      placeholder="123456"
                      className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm font-mono tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                    />
                  </div>
                )}
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    New Secure Passphrase (Min 15 Chars)
                  </label>
                  <input
                    type="password"
                    required
                    autoComplete="new-password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter long passphrase or password manager secret"
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                  />
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1">
                    <span>Length: {newPassword.length} characters</span>
                    <span className={newPassword.length >= 15 ? "text-emerald-400 font-semibold" : "text-amber-400 font-semibold"}>
                      {newPassword.length >= 15 ? "Meets NIST standard" : "Requires 15+ chars"}
                    </span>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Confirm New Passphrase
                  </label>
                  <input
                    type="password"
                    required
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-type new passphrase"
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                  />
                </div>

                <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg text-[11px] text-slate-400 space-y-1">
                  <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
                    <ShieldCheck className="h-3.5 w-3.5 text-blue-400" />
                    NIST SP 800-63B Guidelines:
                  </div>
                  <p>• Minimum 15 characters (or 8 with MFA enabled).</p>
                  <p>• No mandatory symbols or digits required.</p>
                  <p>• Passwords checked against known breach blocklists.</p>
                </div>

                <button
                  type="submit"
                  disabled={changeLoading}
                  className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm shadow-lg shadow-blue-600/30 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
                >
                  {changeLoading ? (
                    <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <>
                      <Lock className="h-4 w-4" />
                      <span>Confirm & Secure Account</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={signOut}
                  className="w-full text-center text-xs text-slate-400 hover:text-slate-200 transition"
                >
                  Sign out instead
                </button>
              </form>
            </div>
          ) : (
            <div>
              {/* Standard Login Step */}
              <div className="mb-5 text-center">
                <h2 className="text-base font-bold text-white tracking-wide">
                  {mfaRequired ? "Multi-Factor Authentication" : "SOC Operator Access"}
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  {mfaRequired 
                    ? "Enter the 6-digit TOTP code generated by your Authenticator application."
                    : "Authenticate to access the Security Orchestration console."}
                </p>
              </div>

              {/* Active Session Notice & Switch Operator Banner */}
              {currentLoggedInUser && (
                <div className="mb-4 p-3 rounded-xl bg-blue-950/40 border border-blue-800/40 flex items-center justify-between text-xs">
                  <div className="overflow-hidden pr-2">
                    <span className="text-slate-400 block text-[11px]">Currently authenticated:</span>
                    <span className="font-bold text-white truncate inline-block max-w-[140px] align-middle">{currentLoggedInUser.username}</span>
                    <span className="text-blue-400 text-[11px] ml-1.5 font-medium">({currentLoggedInUser.role})</span>
                  </div>
                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <button
                      type="button"
                      onClick={() => router.push("/")}
                      className="px-2.5 py-1 rounded bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 font-semibold text-[11px] transition border border-blue-500/30"
                    >
                      Dashboard &rarr;
                    </button>
                    <button
                      type="button"
                      onClick={signOut}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 font-semibold text-[11px] transition border border-slate-700/60"
                      title="Clear session"
                    >
                      Sign Out
                    </button>
                  </div>
                </div>
              )}

              {changeNotice && !error && (
                <div className="mb-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center space-x-2 text-emerald-400 text-xs">
                  <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
                  <span>{changeNotice}</span>
                </div>
              )}

              {error && (
                <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-start space-x-2 text-rose-400 text-xs animate-shake">
                  <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              {success && (
                <div className="mb-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center space-x-2 text-emerald-400 text-xs">
                  <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
                  <span>Authentication authorized. Redirecting to SOC environment...</span>
                </div>
              )}

              <form onSubmit={handleLoginSubmit} className="space-y-4">
                {!mfaRequired ? (
                  <>
                    {/* Username Input */}
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        Operator Identity (Username)
                      </label>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                          <User className="h-4 w-4" />
                        </div>
                        <input
                          type="text"
                          required
                          autoComplete="username"
                          value={username}
                          onChange={(e) => setUsername(e.target.value)}
                          placeholder="Enter operator username..."
                          className="w-full pl-9 pr-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                        />
                      </div>
                    </div>

                    {/* Password Input (Allows Pasting) */}
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        Passphrase / Master Secret
                      </label>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                          <Lock className="h-4 w-4" />
                        </div>
                        <input
                          type={showPassword ? "text" : "password"}
                          required
                          autoComplete="current-password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          placeholder="••••••••••••"
                          className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 transition"
                        >
                          {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  /* MFA Step */
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      6-Digit Authenticator Code (TOTP)
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                        <Smartphone className="h-4 w-4 text-blue-400" />
                      </div>
                      <input
                        type="text"
                        required
                        maxLength={6}
                        autoFocus
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value)}
                        placeholder="123456"
                        className="w-full pl-9 pr-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-center font-mono tracking-widest text-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                      />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-2 text-center">
                      Multi-Factor Authentication is active for account <b className="text-slate-200">{username}</b>.
                    </p>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm shadow-lg shadow-blue-600/30 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
                >
                  {loading ? (
                    <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <>
                      <LogIn className="h-4 w-4" />
                      <span>{mfaRequired ? "Verify Code & Enter" : "Authorize Session"}</span>
                    </>
                  )}
                </button>

                {mfaRequired && (
                  <button
                    type="button"
                    onClick={() => { setMfaRequired(false); setMfaCode(""); }}
                    className="w-full text-center text-xs text-slate-400 hover:text-slate-200 transition mt-2"
                  >
                    ← Back to credentials login
                  </button>
                )}
              </form>
            </div>
          )}
        </div>

        {/* NIST Compliance Badges */}
        <div className="mt-6 flex items-center justify-center space-x-4 text-[11px] text-slate-500">
          <span className="flex items-center gap-1">
            <Radio className="h-3 w-3 text-emerald-400 animate-pulse" />
            NIST SP 800-63B Compliant
          </span>
          <span>•</span>
          <span>Argon2id Cryptography</span>
          <span>•</span>
          <span>RBAC Protection</span>
        </div>
      </div>
    </div>
  );
}
