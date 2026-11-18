"use client";

import React, { useState } from "react";
import { Check, Copy, Loader2, Smartphone } from "lucide-react";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { MfaSetupResponse } from "@/lib/types";
import QrCode from "./QrCode";

/**
 * TOTP enrolment: start (backend creates the secret), scan the QR code or type the secret into an authenticator,
 * then confirm with a current code. MFA only turns on after the code is verified.
 * The secret is kept in component state only and is never logged or stored by the console.
 */
export default function MfaSetup({ onEnabled, onCancel }: { onEnabled: () => void; onCancel?: () => void }) {
  const [setup, setSetup] = useState<MfaSetupResponse | null>(null);
  const [starting, setStarting] = useState(false);
  const [code, setCode] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const start = async () => {
    setStarting(true);
    setError(null);
    try {
      setSetup(await api.setupMfa());
    } catch (err) {
      setError(describeError(err, "Could not start MFA setup."));
    } finally {
      setStarting(false);
    }
  };

  const verify = async (e: React.FormEvent) => {
    e.preventDefault();
    setVerifying(true);
    setError(null);
    try {
      await api.verifyMfa(code.trim());
      setSetup(null);
      setCode("");
      onEnabled();
    } catch (err) {
      setError(describeError(err, "The code could not be verified."));
      setCode("");
    } finally {
      setVerifying(false);
    }
  };

  const copySecret = async () => {
    if (!setup) return;
    try {
      await navigator.clipboard.writeText(setup.secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  if (!setup) {
    return (
      <div className="space-y-3">
        <p className="text-xs text-slate-400 leading-relaxed">
          Multi-factor authentication adds a 6-digit code from an authenticator app (Google Authenticator, Microsoft
          Authenticator, 1Password) to every sign-in. Starting setup generates a new secret; it only takes effect once you
          confirm a code.
        </p>
        {error && (
          <p role="alert" className="text-xs text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-lg p-2.5">
            {error}
          </p>
        )}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={start}
            disabled={starting}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          >
            {starting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Smartphone className="h-4 w-4" />}
            {starting ? "Generating..." : "Generate QR code"}
          </button>
          {onCancel && (
            <button type="button" onClick={onCancel} className="px-3 py-2 rounded-lg text-xs text-slate-400 hover:text-white">
              Cancel
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={verify} className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-4 items-center sm:items-start">
        <QrCode value={setup.provisioning_uri} label={`QR code to add ${setup.account} to an authenticator app`} />
        <div className="space-y-2 text-xs text-slate-300 min-w-0 flex-1">
          <p>
            1. Scan the QR code with your authenticator app, or enter this secret manually (account{" "}
            <b className="text-white">{setup.account}</b>, issuer {setup.issuer}):
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-200 break-all select-all">
              {setup.secret}
            </code>
            <button
              type="button"
              onClick={copySecret}
              aria-label="Copy secret"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
          <p className="text-[11px] text-amber-300">The secret is a password: do not screenshot or share it.</p>
          <p>2. Enter the current 6-digit code to finish:</p>
          <div>
            <label htmlFor="mfa-setup-code" className="sr-only">
              Authenticator code
            </label>
            <input
              id="mfa-setup-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              placeholder="123456"
              className="w-40 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-center font-mono tracking-widest text-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
      </div>
      {error && (
        <p role="alert" className="text-xs text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-lg p-2.5">
          {error}
        </p>
      )}
      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={verifying || code.length !== 6}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
        >
          {verifying && <Loader2 className="h-4 w-4 animate-spin" />}
          {verifying ? "Verifying..." : "Verify and enable MFA"}
        </button>
        <button
          type="button"
          onClick={() => {
            setSetup(null);
            setCode("");
            setError(null);
          }}
          className="px-3 py-2 rounded-lg text-xs text-slate-400 hover:text-white"
        >
          Start over
        </button>
      </div>
    </form>
  );
}
