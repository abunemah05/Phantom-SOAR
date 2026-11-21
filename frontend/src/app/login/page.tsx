"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertCircle,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  LogIn,
  Radio,
  ShieldCheck,
  Smartphone,
  User as UserIcon,
} from "lucide-react";
import { api } from "@/lib/api";
import { clearAuth, getStoredToken, getStoredUser, setStoredAuth, setStoredToken } from "@/lib/auth";
import { describeError } from "@/lib/errors";
import { needsMfaEnrollment, needsPasswordChange } from "@/lib/roles";
import { User } from "@/lib/types";
import BrandMark from "@/components/BrandMark";
import MfaSetup from "@/components/MfaSetup";

type Step = "credentials" | "mfa" | "change_password" | "enroll_mfa";

const INPUT =
  "w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition";
const PRIMARY =
  "w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm shadow-lg shadow-blue-600/30 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300";

/** Minimum length the backend enforces (NIST SP 800-63B): 15 characters, or 8 when MFA protects the account. */
function minPasswordLength(mfaEnabled: boolean): number {
  return mfaEnabled ? 8 : 15;
}

function Notice({ tone, children }: { tone: "error" | "success" | "info"; children: React.ReactNode }) {
  const style = {
    error: "bg-rose-500/10 border-rose-500/30 text-rose-400",
    success: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
    info: "bg-blue-500/10 border-blue-500/30 text-blue-300",
  }[tone];
  const Icon = tone === "error" ? AlertCircle : CheckCircle2;
  return (
    <div role={tone === "error" ? "alert" : "status"} className={`mb-4 p-3 rounded-lg border flex items-start space-x-2 text-xs ${style}`}>
      <Icon className="h-4 w-4 flex-shrink-0 mt-0.5" aria-hidden="true" />
      <span className="break-words">{children}</span>
    </div>
  );
}

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>("credentials");
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [mfaCode, setMfaCode] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [signedIn, setSignedIn] = useState<User | null>(null);

  // Forced password change
  const [accountName, setAccountName] = useState<string>("");
  const [accountMfa, setAccountMfa] = useState<boolean>(false);
  const [askCurrent, setAskCurrent] = useState<boolean>(false);
  const [currentPassword, setCurrentPassword] = useState<string>("");
  const [newPassword, setNewPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [changeMfaCode, setChangeMfaCode] = useState<string>("");

  useEffect(() => {
    const reason = new URLSearchParams(window.location.search).get("reason");
    if (reason === "expired") {
      setNotice("Your session ended (it expired, was signed out, or the password changed). Sign in again.");
    }

    const stored = getStoredUser();
    if (!stored || !getStoredToken()) return;
    setAccountName(stored.username);
    setAccountMfa(Boolean(stored.mfa_enabled));
    if (needsPasswordChange(stored)) {
      // We hold a restricted session but not the password: ask for it.
      setAskCurrent(true);
      setStep("change_password");
    } else if (needsMfaEnrollment(stored) || reason === "mfa") {
      setStep("enroll_mfa");
    } else {
      setSignedIn(stored);
    }
  }, []);

  const finishSignIn = () => {
    setNotice("Signed in. Redirecting to the console...");
    router.push("/");
  };

  /** Decide the next screen from a freshly signed-in profile. */
  const advance = (user: User) => {
    setAccountName(user.username);
    setAccountMfa(Boolean(user.mfa_enabled));
    if (needsPasswordChange(user)) {
      setAskCurrent(false);
      setStep("change_password");
    } else if (needsMfaEnrollment(user)) {
      setStep("enroll_mfa");
    } else {
      finishSignIn();
    }
  };

  const signOut = async () => {
    await api.logout();
    setSignedIn(null);
    setStep("credentials");
    setPassword("");
    setMfaCode("");
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setError(null);
    setNotice(null);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.login(username.trim(), password, step === "mfa" ? mfaCode.trim() : undefined);
      if (res.mfa_required) {
        setStep("mfa");
        setMfaCode("");
        return;
      }
      if (!res.access_token || !res.user) {
        setError("The server did not return a session. Try again.");
        return;
      }
      const user: User = {
        ...res.user,
        mfa_enrollment_required: res.mfa_enrollment_required ?? res.user.mfa_enrollment_required ?? false,
      };
      setStoredAuth(user, res.access_token);
      setMfaCode("");
      advance(user);
    } catch (err) {
      setError(describeError(err, "Authentication failed."));
      if (step === "mfa") setMfaCode("");
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (newPassword !== confirmPassword) {
      setError("The new password and its confirmation do not match.");
      return;
    }
    const min = minPasswordLength(accountMfa);
    if (newPassword.length < min) {
      setError(`The new password must be at least ${min} characters${accountMfa ? "" : " (8 once MFA is enabled)"}.`);
      return;
    }
    setLoading(true);
    try {
      // The Bearer session identifies the account; the backend never trusts a username from the body.
      const current = askCurrent ? currentPassword : password || currentPassword;
      const res = await api.changePassword({
        ...(current ? { current_password: current } : {}),
        new_password: newPassword,
        ...(changeMfaCode.trim() ? { mfa_code: changeMfaCode.trim() } : {}),
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setChangeMfaCode("");
      setPassword("");

      // The backend invalidated earlier sessions and returns a fresh one.
      if (res.access_token) {
        setStoredToken(res.access_token);
        const me = await api.getCurrentUser(); // authoritative profile, including mfa_enrollment_required
        setStoredAuth(me, res.access_token);
        advance(me);
      } else {
        clearAuth();
        setStep("credentials");
        setUsername(accountName);
        setNotice("Password updated. Sign in again with your new password.");
      }
    } catch (err) {
      setError(describeError(err, "Could not update the password."));
    } finally {
      setLoading(false);
    }
  };

  const handleMfaEnabled = async () => {
    setError(null);
    try {
      const me = await api.getCurrentUser();
      const token = getStoredToken();
      if (token) setStoredAuth(me, token);
      advance(me);
    } catch (err) {
      setError(describeError(err, "MFA is enabled, but the profile could not be refreshed. Sign in again."));
    }
  };

  const minLen = minPasswordLength(accountMfa);

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center px-4 sm:px-6 lg:px-8 relative overflow-hidden font-sans">
      <div className="absolute inset-0 bg-[radial-gradient(#262626_1px,transparent_1px)] [background-size:24px_24px] opacity-25 pointer-events-none" aria-hidden="true" />
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" aria-hidden="true" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" aria-hidden="true" />

      <div className="w-full max-w-md z-10">
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center h-14 w-14 rounded-2xl bg-black shadow-xl shadow-blue-500/25 mb-3 border border-slate-700">
            <BrandMark className="h-8 w-8" />
          </div>
          <h1 className="text-2xl font-black tracking-wider text-white flex items-center justify-center space-x-2">
            <span>PHANTOM</span>
            <span className="font-light text-slate-400">SOAR</span>
          </h1>
          <p className="text-xs text-slate-400 font-medium tracking-wide mt-1">Security Orchestration, Automation & Response</p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl shadow-2xl p-7 backdrop-blur-xl">
          {/* ---- Forced password change ---- */}
          {step === "change_password" && (
            <div>
              <div className="mb-5 text-center">
                <div className="inline-flex p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20 mb-2">
                  <KeyRound className="h-5 w-5" aria-hidden="true" />
                </div>
                <h2 className="text-base font-bold text-white">Set a new password</h2>
                <p className="text-xs text-slate-400 mt-1">
                  This account must choose a new password before it can use the console. Length matters more than symbols: use a
                  passphrase of at least {minLen} characters. Pasting from a password manager works.
                </p>
              </div>

              {error && <Notice tone="error">{error}</Notice>}

              <form onSubmit={handleChangePassword} className="space-y-4">
                <div className="text-[11px] text-slate-400">
                  Account: <b className="text-slate-200">{accountName}</b>
                </div>
                {askCurrent && (
                  <div>
                    <label htmlFor="current-password" className="block text-xs font-semibold text-slate-300 mb-1">
                      Current (temporary) password
                    </label>
                    <input
                      id="current-password"
                      type="password"
                      required
                      autoComplete="current-password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      className={INPUT}
                    />
                  </div>
                )}
                {accountMfa && (
                  <div>
                    <label htmlFor="change-mfa" className="block text-xs font-semibold text-slate-300 mb-1">
                      Authenticator code {askCurrent ? "" : "(only if the server asks for it)"}
                    </label>
                    <input
                      id="change-mfa"
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={6}
                      value={changeMfaCode}
                      onChange={(e) => setChangeMfaCode(e.target.value.replace(/\D/g, ""))}
                      placeholder="123456"
                      className={`${INPUT} font-mono tracking-widest`}
                    />
                  </div>
                )}
                <div>
                  <label htmlFor="new-password" className="block text-xs font-semibold text-slate-300 mb-1">
                    New password (at least {minLen} characters)
                  </label>
                  <input
                    id="new-password"
                    type="password"
                    required
                    autoComplete="new-password"
                    autoFocus={!askCurrent}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className={INPUT}
                    aria-describedby="new-password-hint"
                  />
                  <div id="new-password-hint" className="flex items-center justify-between text-[11px] text-slate-400 mt-1">
                    <span>Length: {newPassword.length}</span>
                    <span className={newPassword.length >= minLen ? "text-emerald-400 font-semibold" : "text-amber-400 font-semibold"}>
                      {newPassword.length >= minLen ? "Long enough" : `Needs ${minLen}+ characters`}
                    </span>
                  </div>
                </div>
                <div>
                  <label htmlFor="confirm-password" className="block text-xs font-semibold text-slate-300 mb-1">
                    Confirm new password
                  </label>
                  <input
                    id="confirm-password"
                    type="password"
                    required
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={INPUT}
                  />
                </div>

                <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg text-[11px] text-slate-400 space-y-1">
                  <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
                    <ShieldCheck className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                    Password rules (NIST SP 800-63B)
                  </div>
                  <p>No forced symbols or digits. The server rejects common and breached passwords.</p>
                  <p>Changing the password signs out every other session of this account.</p>
                </div>

                <button type="submit" disabled={loading} className={PRIMARY}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" aria-hidden="true" />}
                  <span>{loading ? "Saving..." : "Save new password"}</span>
                </button>
                <button type="button" onClick={signOut} className="w-full text-center text-xs text-slate-400 hover:text-slate-200 transition">
                  Sign out instead
                </button>
              </form>
            </div>
          )}

          {/* ---- Mandatory MFA enrolment ---- */}
          {step === "enroll_mfa" && (
            <div>
              <div className="mb-5 text-center">
                <div className="inline-flex p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20 mb-2">
                  <Smartphone className="h-5 w-5" aria-hidden="true" />
                </div>
                <h2 className="text-base font-bold text-white">Set up multi-factor authentication</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Administrators must protect their account with an authenticator app before using the console.
                </p>
              </div>
              {error && <Notice tone="error">{error}</Notice>}
              <MfaSetup onEnabled={handleMfaEnabled} />
              <button type="button" onClick={signOut} className="w-full text-center text-xs text-slate-400 hover:text-slate-200 transition mt-4">
                Sign out instead
              </button>
            </div>
          )}

          {/* ---- Credentials / MFA code ---- */}
          {(step === "credentials" || step === "mfa") && (
            <div>
              <div className="mb-5 text-center">
                <h2 className="text-base font-bold text-white tracking-wide">
                  {step === "mfa" ? "Multi-factor authentication" : "SOC operator sign-in"}
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  {step === "mfa"
                    ? "Enter the 6-digit code from your authenticator app."
                    : "Authenticate to access the Security Orchestration console."}
                </p>
              </div>

              {signedIn && (
                <div className="mb-4 p-3 rounded-xl bg-blue-950/40 border border-blue-800/40 flex items-center justify-between text-xs">
                  <div className="overflow-hidden pr-2">
                    <span className="text-slate-400 block text-[11px]">Currently signed in:</span>
                    <span className="font-bold text-white truncate inline-block max-w-[140px] align-middle">{signedIn.username}</span>
                    <span className="text-blue-400 text-[11px] ml-1.5 font-medium">({signedIn.role})</span>
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
                    >
                      Sign out
                    </button>
                  </div>
                </div>
              )}

              {notice && !error && <Notice tone="info">{notice}</Notice>}
              {error && <Notice tone="error">{error}</Notice>}

              <form onSubmit={handleLogin} className="space-y-4">
                {step === "credentials" ? (
                  <>
                    <div>
                      <label htmlFor="username" className="block text-xs font-semibold text-slate-300 mb-1">
                        Username
                      </label>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                          <UserIcon className="h-4 w-4" aria-hidden="true" />
                        </div>
                        <input
                          id="username"
                          type="text"
                          required
                          autoFocus
                          autoComplete="username"
                          value={username}
                          onChange={(e) => setUsername(e.target.value)}
                          className={`${INPUT} pl-9`}
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="password" className="block text-xs font-semibold text-slate-300 mb-1">
                        Password
                      </label>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                          <Lock className="h-4 w-4" aria-hidden="true" />
                        </div>
                        <input
                          id="password"
                          type={showPassword ? "text" : "password"}
                          required
                          autoComplete="current-password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          className={`${INPUT} pl-9 pr-10`}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          aria-label={showPassword ? "Hide password" : "Show password"}
                          aria-pressed={showPassword}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 transition focus:outline-none focus-visible:text-white"
                        >
                          {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  <div>
                    <label htmlFor="mfa-code" className="block text-xs font-semibold text-slate-300 mb-1">
                      6-digit authenticator code
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                        <Smartphone className="h-4 w-4 text-blue-400" aria-hidden="true" />
                      </div>
                      <input
                        id="mfa-code"
                        type="text"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        required
                        maxLength={6}
                        autoFocus
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                        placeholder="123456"
                        className={`${INPUT} pl-9 text-center font-mono tracking-widest text-lg`}
                      />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-2 text-center">
                      MFA is active for <b className="text-slate-200">{username}</b>. A code works once.
                    </p>
                  </div>
                )}

                <button type="submit" disabled={loading || (step === "mfa" && mfaCode.length !== 6)} className={`${PRIMARY} mt-2`}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <LogIn className="h-4 w-4" aria-hidden="true" />}
                  <span>{step === "mfa" ? "Verify code" : "Sign in"}</span>
                </button>

                {step === "mfa" && (
                  <button
                    type="button"
                    onClick={() => {
                      setStep("credentials");
                      setMfaCode("");
                      setError(null);
                    }}
                    className="w-full text-center text-xs text-slate-400 hover:text-slate-200 transition mt-2"
                  >
                    &larr; Back to password
                  </button>
                )}
              </form>
            </div>
          )}
        </div>

        <div className="mt-6 flex items-center justify-center space-x-4 text-[11px] text-slate-500">
          <span className="flex items-center gap-1">
            <Radio className="h-3 w-3 text-emerald-400" aria-hidden="true" />
            NIST SP 800-63B password guidance
          </span>
          <span aria-hidden="true">&bull;</span>
          <span>Argon2id hashing</span>
          <span aria-hidden="true">&bull;</span>
          <span>Role-based access</span>
        </div>
      </div>
    </div>
  );
}
