// Error handling shared by every page: one place that understands the backend's error shapes.
//
// FastAPI answers errors as {"detail": ...} where detail is
//   - a string                                   (HTTPException(detail="..."))
//   - a list of {loc, msg, type}                 (422 validation errors)
//   - an object {message, blockers?, ...}        (409 from hotl-toggle / configuration save / NVD response)

export interface ParsedErrorDetail {
  message: string;
  /** Reasons an action was refused (e.g. HOTL cannot be enabled yet). */
  blockers: string[];
  /** Stable machine-readable reason when the backend sends one (account policy: "self_role_change", "step_up_failed", ...). */
  code?: string;
}

export class ApiError extends Error {
  /** HTTP status, or 0 when the API could not be reached at all. */
  status: number;
  blockers: string[];
  retryAfterSeconds?: number;
  /** Machine-readable reason from the backend, when it sent one. */
  code?: string;

  constructor(status: number, message: string, extra?: { blockers?: string[]; retryAfterSeconds?: number; code?: string }) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.blockers = extra?.blockers ?? [];
    this.retryAfterSeconds = extra?.retryAfterSeconds;
    this.code = extra?.code;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).filter((v) => v.length > 0);
}

function validationMessage(item: unknown): string {
  if (!isRecord(item)) return typeof item === 'string' ? item : JSON.stringify(item);
  const msg = typeof item.msg === 'string' ? item.msg : JSON.stringify(item);
  const loc = Array.isArray(item.loc) ? item.loc.filter((p) => p !== 'body' && p !== 'query').join('.') : '';
  return loc ? `${loc}: ${msg}` : msg;
}

/** Turn a response body into a human message. Never returns raw HTML or an empty string. */
export function parseErrorBody(status: number, bodyText: string): ParsedErrorDetail {
  const fallback = `Request failed (HTTP ${status}).`;
  const text = (bodyText || '').trim();
  if (!text) return { message: fallback, blockers: [] };

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    // Not JSON (proxy error page, plain text): show short plain text only.
    if (text.startsWith('<') || text.length > 300) return { message: fallback, blockers: [] };
    return { message: text, blockers: [] };
  }

  const detail = isRecord(json) ? (json.detail ?? json.message) : json;
  if (typeof detail === 'string') return { message: detail || fallback, blockers: [] };
  if (Array.isArray(detail)) {
    const message = detail.map(validationMessage).join('; ');
    return { message: message || fallback, blockers: [] };
  }
  if (isRecord(detail)) {
    const message = typeof detail.message === 'string' && detail.message ? detail.message : fallback;
    const code = typeof detail.code === 'string' && detail.code ? detail.code : undefined;
    return { message, blockers: asStringList(detail.blockers), ...(code ? { code } : {}) };
  }
  return { message: fallback, blockers: [] };
}

/** Parse a Retry-After header (delta-seconds or HTTP date). Returns whole seconds, at least 1. */
export function parseRetryAfter(value: string | null | undefined, now: number = Date.now()): number | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Math.max(1, parseInt(trimmed, 10));
  const when = Date.parse(trimmed);
  if (Number.isNaN(when)) return undefined;
  return Math.max(1, Math.ceil((when - now) / 1000));
}

export const NETWORK_ERROR_MESSAGE =
  'Cannot reach the Phantom SOAR API. Check that the backend is running and that this browser may connect to it.';

/** Message for any thrown value (ApiError, network failure, plain Error). */
export function describeError(err: unknown, fallback = 'The request failed.'): string {
  if (err instanceof ApiError) {
    if (err.status === 429 && err.retryAfterSeconds) {
      return `${err.message} Retry in ${err.retryAfterSeconds}s.`;
    }
    return err.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

/** Blockers list of an ApiError (empty for anything else). */
export function errorBlockers(err: unknown): string[] {
  return err instanceof ApiError ? err.blockers : [];
}

export function isUnauthorized(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401;
}

/** The backend refused only because a sensitive account change needs the administrator's own password / MFA code. */
export function isStepUpRequired(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 428 || err.code === 'step_up_required' || err.code === 'step_up_failed');
}

export function isForbidden(err: unknown): boolean {
  return err instanceof ApiError && err.status === 403;
}

/** True when the backend refused only because the session still owes a password change. */
export function isPasswordChangeRequired(status: number, message: string): boolean {
  return status === 403 && message.toLowerCase().includes('password change required');
}

/** True when the backend refused because administrators must enrol MFA first. */
export function isMfaEnrollmentRequired(status: number, message: string): boolean {
  const m = message.toLowerCase();
  return status === 403 && m.includes('multi-factor') && m.includes('enrol');
}
