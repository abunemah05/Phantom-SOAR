# Frontend security notes

## Session token storage

The access token lives in `sessionStorage` (key `phantom_soar_token`, profile cache `phantom_user`).
It is scoped to one tab and disappears when the tab closes. The old duplicated key in `localStorage` is
removed on every load and is never written. Tokens are never logged, put in URLs or shipped in client code.

`sessionStorage` is still readable by any script that runs on the page, so an XSS bug would expose the
token. The mitigations in place:

- A Content-Security-Policy and the other headers set in `next.config.js` (`headers()`): `default-src 'self'`,
  `connect-src` limited to this origin plus `NEXT_PUBLIC_API_URL`, `object-src 'none'`, `frame-ancestors 'none'`,
  `base-uri 'self'`, `form-action 'self'`, plus `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
  and `X-Frame-Options`.
- No `dangerouslySetInnerHTML`. Model-written and alert-derived text is always rendered as plain text. The MFA
  QR code is drawn as inline SVG from a data matrix, not injected HTML.
- `script-src` still needs `'unsafe-inline'`: the Next.js App Router streams inline bootstrap scripts, and a
  per-request nonce would require a middleware and dynamic rendering for every page. Moving to nonces is a
  follow-up.

## Recommended next step: httpOnly cookie session

Move the session to an `httpOnly; Secure; SameSite=Strict` cookie set by the backend. Then script cannot read
it at all, which closes the main residual XSS risk. It was deferred because it changes the backend contract
and is not a frontend-only change:

- the backend must set and clear the cookie on login, logout, password change and MFA changes;
- cookie auth is exposed to CSRF, so state-changing routes need a CSRF token (double-submit or a custom
  header the browser will not send cross-site) and an explicit CORS allow-list with credentials;
- the AI agent API keeps using the `X-Phantom-Agent-Key` header (it is not browser based);
- the dev proxy (`rewrites`) and the Docker deployment need the frontend and API to share a site.

Until then, `sessionStorage` plus the CSP above is the compromise.

## Other rules this code follows

- Every destructive or high-impact action asks for confirmation in an in-app dialog that states what will
  happen. The backend remains the authority: hiding a button is a convenience, not an access control.
- Secrets (API keys, ingest tokens, temporary passwords, MFA secrets) are shown once and kept in component
  state only. Configuration secrets are write-only and are never echoed back.
- A 401 clears the session and returns to `/login`.
