import { User } from "./types";

export const TOKEN_KEY = "phantom_soar_token";
export const LEGACY_TOKEN_KEY = "phantom_token";
export const USER_KEY = "phantom_user";
export const AUTH_CHANGE_EVENT = "phantom-auth-change";

export function getStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY) || localStorage.getItem(LEGACY_TOKEN_KEY);
}

export function setStoredToken(token: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(LEGACY_TOKEN_KEY, token);
}

export function clearStoredToken(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(LEGACY_TOKEN_KEY);
}

export function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

export function setStoredAuth(user: User, token: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(LEGACY_TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));

  window.dispatchEvent(
    new CustomEvent(AUTH_CHANGE_EVENT, { detail: user })
  );
}

export function setStoredUser(user: User): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  window.dispatchEvent(
    new CustomEvent(AUTH_CHANGE_EVENT, { detail: user })
  );
}

export function clearAuth(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(LEGACY_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);

  window.dispatchEvent(
    new CustomEvent(AUTH_CHANGE_EVENT, { detail: null })
  );
}

export function subscribeToAuth(callback: (user: User | null) => void): () => void {
  if (typeof window === "undefined") return () => {};

  const handleCustomEvent = (event: Event) => {
    const customEvent = event as CustomEvent<User | null>;
    callback(customEvent.detail ?? getStoredUser());
  };

  const handleStorageEvent = (event: StorageEvent) => {
    if (event.key === USER_KEY || event.key === TOKEN_KEY || event.key === LEGACY_TOKEN_KEY) {
      callback(getStoredUser());
    }
  };

  window.addEventListener(AUTH_CHANGE_EVENT, handleCustomEvent);
  window.addEventListener("storage", handleStorageEvent);

  return () => {
    window.removeEventListener(AUTH_CHANGE_EVENT, handleCustomEvent);
    window.removeEventListener("storage", handleStorageEvent);
  };
}
