"use client";

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { api, getStoredToken, getStoredUser, subscribeToAuth, syncCurrentUser, LOGIN_PATH } from "@/lib/api";
import { needsPasswordChange } from "@/lib/roles";
import { User } from "@/lib/types";

interface AuthContextValue {
  user: User | null;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  logout: async () => {},
});

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}

/**
 * Client-side session gate. Every route except /login requires a stored token that the
 * backend still accepts (/auth/me), and an account that does not owe a password change.
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
    const stored = getStoredUser();
    if (!token || needsPasswordChange(stored)) {
      sendToLogin();
      return;
    }

    syncCurrentUser().then((live) => {
      if (cancelled) return;
      if (!live || needsPasswordChange(live)) {
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
      if ((!updated || needsPasswordChange(updated)) && window.location.pathname !== LOGIN_PATH) {
        sendToLogin();
      }
    });
  }, [sendToLogin]);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
    sendToLogin();
  }, [sendToLogin]);

  if (isPublic) {
    return <AuthContext.Provider value={{ user, logout }}>{children}</AuthContext.Provider>;
  }

  if (!verified) {
    return (
      <div className="min-h-screen w-full flex flex-col items-center justify-center space-y-3 bg-slate-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
        <p className="text-sm text-slate-400">Verifying session...</p>
      </div>
    );
  }

  return <AuthContext.Provider value={{ user, logout }}>{children}</AuthContext.Provider>;
}
