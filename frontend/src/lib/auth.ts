import { User } from "./types";

// Session storage for the console.
//
// The bearer token and the cached profile live in sessionStorage: they die with the tab and are never shared
// with other tabs or persisted to disk. They are readable by any script running on this origin, which is why
// the Content-Security-Policy in next.config.js matters; see frontend/SECURITY-NOTES.md for why an
// httpOnly-cookie session is the recommended next step. Nothing here ever logs a token.

export const TOKEN_KEY = "phantom_soar_token";
export const USER_KEY = "phantom_user";
export const AUTH_CHANGE_EVENT = "phantom-auth-change";

// Keys written by earlier builds to localStorage (including the duplicated legacy token key).
const LEGACY_LOCAL_KEYS = ["phantom_soar_token", "phantom_token", "phantom_user"];

function session(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null; // storage disabled
  }
}

let legacyPurged = false;
/** Remove tokens and profiles that older builds left in localStorage (readable by every tab, never expiring). */
export function purgeLegacyStorage(): void {
  if (legacyPurged || typeof window === "undefined") return;
  legacyPurged = true;
  try {
    LEGACY_LOCAL_KEYS.forEach((key) => window.localStorage.removeItem(key));
  } catch {
    // storage disabled: nothing to purge
  }
}

function emit(user: User | null): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(AUTH_CHANGE_EVENT, { detail: user }));
}

export function getStoredToken(): string | null {
  purgeLegacyStorage();
  return session()?.getItem(TOKEN_KEY) || null;
}

export function setStoredToken(token: string): void {
  session()?.setItem(TOKEN_KEY, token);
}

export function clearStoredToken(): void {
  session()?.removeItem(TOKEN_KEY);
}

export function getStoredUser(): User | null {
  purgeLegacyStorage();
  const raw = session()?.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

export function setStoredAuth(user: User, token: string): void {
  const store = session();
  if (!store) return;
  store.setItem(TOKEN_KEY, token);
  store.setItem(USER_KEY, JSON.stringify(user));
  emit(user);
}

export function setStoredUser(user: User): void {
  session()?.setItem(USER_KEY, JSON.stringify(user));
  emit(user);
}

export function clearAuth(): void {
  const store = session();
  store?.removeItem(TOKEN_KEY);
  store?.removeItem(USER_KEY);
  emit(null);
}

export function subscribeToAuth(callback: (user: User | null) => void): () => void {
  if (typeof window === "undefined") return () => {};

  const handler = (event: Event) => {
    const detail = (event as CustomEvent<User | null>).detail;
    callback(detail ?? getStoredUser());
  };

  window.addEventListener(AUTH_CHANGE_EVENT, handler);
  return () => window.removeEventListener(AUTH_CHANGE_EVENT, handler);
}
