"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { api, getStoredToken, getStoredUser, subscribeToAuth, syncCurrentUser, LOGIN_PATH } from "@/lib/api";
import { needsMfaEnrollment, needsPasswordChange } from "@/lib/roles";
import { User } from "@/lib/types";

interface AuthContextValue {
  user: User | null;
  logout: () => Promise<void>;
  /** Re-read the profile from the backend (e.g. after enabling or disabling MFA). */
  refreshUser: () => Promise<User | null>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  logout: async () => {},
  refreshUser: async () => null,
});

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}

/** A session that may not use the console yet: the sign-in page owns the password and MFA enrolment forms. */
function mustFinishSignIn(user: User | null): boolean {
  return needsPasswordChange(user) || needsMfaEnrollment(user);
}

/**
 * Client-side session gate. Every route except /login requires a stored token that the backend still accepts
 * (/auth/me) and an account that owes neither a password change nor mandatory MFA enrolment.
 * The backend enforces the same rules on every request; this only keeps the UI consistent.
 */
export default function AuthGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isPublic = pathname === LOGIN_PATH;

  const [user, setUser] = useState<User | null>(null);
  const [verified, setVerified] = useState<boolean>(false);

  const sendToLogin = useCallback(() => {
    setVerified(false);
    router.replace(LOGIN_PATH);
  }, [router]);

  useEffect(() => {
    if (isPublic) {
      setVerified(false);
      return;
    }
    let cancelled = false;

    const token = getStoredToken();
    if (!token || mustFinishSignIn(getStoredUser())) {
      sendToLogin();
      return;
    }

    syncCurrentUser().then((live) => {
      if (cancelled) return;
      if (!live || mustFinishSignIn(live)) {
        sendToLogin();
        return;
      }
      setUser(live);
      setVerified(true);
    });

    return () => {
      cancelled = true;
    };
  }, [isPublic, sendToLogin]);

  useEffect(() => {
    return subscribeToAuth((updated) => {
      setUser(updated);
      if ((!updated || mustFinishSignIn(updated)) && window.location.pathname !== LOGIN_PATH) {
        sendToLogin();
      }
    });
  }, [sendToLogin]);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
    sendToLogin();
  }, [sendToLogin]);

  const refreshUser = useCallback(async () => {
    const live = await syncCurrentUser();
    setUser(live);
    return live;
  }, []);

  const value = useMemo(() => ({ user, logout, refreshUser }), [user, logout, refreshUser]);

  if (isPublic) {
    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
  }

  if (!verified) {
    return (
      <div role="status" className="min-h-screen w-full flex flex-col items-center justify-center space-y-3 bg-slate-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" aria-hidden="true" />
        <p className="text-sm text-slate-400">Verifying session...</p>
      </div>
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
