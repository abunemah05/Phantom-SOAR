"use client";

import React, { useRef, useState } from "react";
import { KeyRound, Loader2, ShieldCheck, ShieldOff } from "lucide-react";
import { api, setStoredToken } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { accessLabel } from "@/lib/roles";
import { useAuth } from "@/components/AuthGate";
import Dialog from "@/components/Dialog";
import MfaSetup from "@/components/MfaSetup";
import { InlineNotice } from "@/components/StateViews";
import { useConfirm } from "@/components/ConfirmDialog";
import { useToast } from "@/components/Toast";

const INPUT =
  "w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition";

/** Same rule the backend enforces (NIST SP 800-63B): 15 characters, or 8 when MFA protects the account. */
function minPasswordLength(mfaEnabled: boolean): number {
  return mfaEnabled ? 8 : 15;
}

export default function SecurityPage() {
  const { user, refreshUser } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();

  const mfaOn = Boolean(user?.mfa_enabled);
  const [enrolling, setEnrolling] = useState(false);
  const [disabling, setDisabling] = useState(false);

  const onMfaEnabled = async () => {
    setEnrolling(false);
    await refreshUser();
    toast.success("Multi-factor authentication is now on for your account.");
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
          <KeyRound className="h-6 w-6 text-blue-400" aria-hidden="true" />
          My Security
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Signed in as <b className="text-slate-200">{user?.username}</b> ({accessLabel(user)}). Session tokens are kept in this tab only and end when it closes.
        </p>
      </div>

      <section aria-labelledby="mfa-heading" className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            {mfaOn ? (
              <ShieldCheck className="h-6 w-6 text-emerald-400 mt-0.5" aria-hidden="true" />
            ) : (
              <ShieldOff className="h-6 w-6 text-amber-400 mt-0.5" aria-hidden="true" />
            )}
            <div>
              <h2 id="mfa-heading" className="text-base font-bold text-white">Multi-factor authentication</h2>
              <p className="text-xs text-slate-400 mt-1">
                {mfaOn
                  ? "A six-digit code from your authenticator app is required at sign-in."
                  : "Not enabled. A second factor protects the account if the password leaks, and lowers the minimum password length to 8 characters."}
              </p>
            </div>
          </div>
          {mfaOn ? (
            <button
              type="button"
              onClick={() => setDisabling(true)}
              className="px-4 py-2 rounded-lg bg-rose-500/10 hover:bg-rose-600 border border-rose-500/30 text-rose-300 hover:text-white text-xs font-semibold flex-shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
            >
              Disable MFA
            </button>
          ) : (
            !enrolling && (
              <button
                type="button"
                onClick={() => setEnrolling(true)}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex-shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
              >
                Set up MFA
              </button>
            )
          )}
        </div>
        {enrolling && !mfaOn && <MfaSetup onEnabled={() => void onMfaEnabled()} onCancel={() => setEnrolling(false)} />}
      </section>

      <ChangePasswordCard mfaOn={mfaOn} onChanged={() => void refreshUser()} />

      <DisableMfaDialog
        open={disabling}
        onClose={() => setDisabling(false)}
        confirmFirst={() =>
          confirm({
            title: "Disable multi-factor authentication?",
            message: "Your account will accept a password alone at sign-in. If policy requires MFA for administrators you will be asked to enrol again immediately.",
            confirmLabel: "Disable MFA",
            tone: "danger",
          })
        }
        onDisabled={async () => {
          setDisabling(false);
          await refreshUser();
          toast.success("Multi-factor authentication was turned off.");
        }}
      />
    </div>
  );
}

function ChangePasswordCard({ mfaOn, onChanged }: { mfaOn: boolean; onChanged: () => void }) {
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next !== again) {
      setError("The new password and its confirmation do not match.");
      return;
    }
    const min = minPasswordLength(mfaOn);
    if (next.length < min) {
      setError(`The new password must be at least ${min} characters${mfaOn ? "" : " (8 once MFA is enabled)"}.`);
      return;
    }
    setBusy(true);
    try {
      const res = await api.changePassword({
        current_password: current,
        new_password: next,
        ...(mfaOn && code.trim() ? { mfa_code: code.trim() } : {}),
      });
      // Earlier sessions were invalidated; keep working with the fresh one.
      if (res.access_token) setStoredToken(res.access_token);
      setCurrent("");
      setNext("");
      setAgain("");
      setCode("");
      onChanged();
      toast.success("Password updated. Other sessions were signed out.");
    } catch (err) {
      setError(describeError(err, "Could not update the password."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby="pw-heading" className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
      <h2 id="pw-heading" className="text-base font-bold text-white">Change password</h2>
      <p className="text-xs text-slate-400 mt-1">
        At least {minPasswordLength(mfaOn)} characters. Length matters more than symbols; known-breached passwords and ones containing your username are refused.
      </p>
      <form onSubmit={submit} className="mt-4 space-y-3" autoComplete="off">
        {error && <InlineNotice tone="error" onDismiss={() => setError(null)}>{error}</InlineNotice>}
        <div>
          <label htmlFor="pw-current" className="block text-xs font-semibold text-slate-300 mb-1">Current password</label>
          <input id="pw-current" type="password" required autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} className={INPUT} />
        </div>
        <div>
          <label htmlFor="pw-new" className="block text-xs font-semibold text-slate-300 mb-1">New password</label>
          <input id="pw-new" type="password" required autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} className={INPUT} />
        </div>
        <div>
          <label htmlFor="pw-again" className="block text-xs font-semibold text-slate-300 mb-1">Confirm new password</label>
          <input id="pw-again" type="password" required autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} className={INPUT} />
        </div>
        {mfaOn && (
          <div>
            <label htmlFor="pw-code" className="block text-xs font-semibold text-slate-300 mb-1">Authenticator code</label>
            <input id="pw-code" inputMode="numeric" required autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} className={`${INPUT} font-mono tracking-widest`} />
          </div>
        )}
        <button
          type="submit"
          disabled={busy || !current || !next || !again || (mfaOn && code.length !== 6)}
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
        >
          {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
          Update password
        </button>
      </form>
    </section>
  );
}

function DisableMfaDialog({
  open,
  onClose,
  onDisabled,
  confirmFirst,
}: {
  open: boolean;
  onClose: () => void;
  onDisabled: () => Promise<void>;
  confirmFirst: () => Promise<boolean>;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const firstRef = useRef<HTMLInputElement>(null);

  const close = () => {
    setPassword("");
    setCode("");
    setError(null);
    onClose();
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!(await confirmFirst())) return;
    setBusy(true);
    try {
      await api.disableMfa({ password, code: code.trim() });
      setPassword("");
      setCode("");
      await onDisabled();
    } catch (err) {
      setError(describeError(err, "Could not disable MFA."));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      title="Disable multi-factor authentication"
      description="Prove it is you: the account password and a current authenticator code are both required."
      size="sm"
      initialFocusRef={firstRef}
    >
      <form onSubmit={submit} className="space-y-3" autoComplete="off">
        {error && <InlineNotice tone="error">{error}</InlineNotice>}
        <div>
          <label htmlFor="dis-pw" className="block text-xs font-semibold text-slate-300 mb-1">Password</label>
          <input ref={firstRef} id="dis-pw" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className={INPUT} />
        </div>
        <div>
          <label htmlFor="dis-code" className="block text-xs font-semibold text-slate-300 mb-1">Authenticator code</label>
          <input id="dis-code" inputMode="numeric" required autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} className={`${INPUT} font-mono tracking-widest`} />
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={close} className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || !password || code.length !== 6}
            className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
          >
            {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
            Disable MFA
          </button>
        </div>
      </form>
    </Dialog>
  );
}
