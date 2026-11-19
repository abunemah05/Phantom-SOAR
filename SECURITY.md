# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in public issues. Use GitHub's **Report a vulnerability**
(private vulnerability reporting) on the repository's Security tab if it is enabled, or contact the owner at the address
below.

> **Owner: add the security contact here** (an address you read). This placeholder is intentionally empty; no contact
> has been invented for you.

Include the affected version or commit, steps to reproduce and the impact. Do not include real credentials or customer
data. Please allow reasonable time for a fix before publishing details. Phantom SOAR has had no independent security
audit; the review that produced this branch was done by the authors and their tooling.

## What is being protected, and from whom

Phantom SOAR can block addresses, isolate hosts, kill processes and disable accounts, and it stores credentials for
the systems that do it. Whoever controls it can cause outages and read your alerts, so the aims are:

1. Only authorised people and senders can read data or trigger actions.
2. An attacker who controls **alert contents** (log lines, file names, user names) cannot make the platform do harm.
3. A stolen database backup or a leaked log does not hand over integration credentials.
4. Automation cannot cut the platform or its operators off from the network.

| Threat | Main defences in the code |
|---|---|
| Stolen or guessed passwords | Argon2id, 15-character minimum (8 with MFA), common-password blocklist, TOTP MFA (can be made mandatory for admins), per-user/address lockout and rate limits, uniform responses and timing for unknown users |
| Stolen session token | 12-hour tokens (`PHANTOM_JWT_EXPIRE_MINUTES`), revocation at logout stored in the database, role re-read on every request, token held in `sessionStorage` (dies with the tab) |
| Forged alerts | per-sender ingest tokens (hashed, revocable, optional expiry), failed-token throttling, body size cap; alerts alone cannot cause autonomous action (HOTL is off by default, ignored at run time until protected assets are listed, and needs live threat-intel evidence) |
| Attacker-controlled alert text | text is data: playbook choice by strong signals first, AI prompts keep alert text out of the system prompt and in nonce-delimited data blocks, model output is schema-validated and passes the same policy check |
| Privilege escalation through account management | one policy file (`backend/rbac.py`): no self-escalation, the last and the bootstrap administrator are protected (race-safe), AI-agent accounts are fixed-role and can never be administrators or manage accounts, changes to another administrator (including deleting one) and every grant of the Admin role (including creating an Admin account) need the acting admin's own password (and MFA code) and are audit-logged; creating service accounts and rotating their keys is audit-logged but not step-up gated (known limitation), only named roles can be assigned, only whitelisted fields can be updated. Details, sources and limits: [docs/ACCESS_CONTROL.md](docs/ACCESS_CONTROL.md) |
| Runaway or malicious automation | policy engine: protected hosts/users/IPs, automatic protection of the Wazuh manager, this server, loopback and gateway, confidence and autonomy limits for agents, automation limited to the alert's own Wazuh agent, simulation mode (a hard stop for all response actions), HOTL master switch with preconditions enforced at run time |
| Database or backup leak | integration secrets and MFA seeds are Fernet-encrypted (`PHANTOM_ENCRYPTION_KEY`); password hashes are Argon2id; API keys and ingest tokens stored as hashes; API never returns stored secrets (masked previews only) |
| Abuse of the "test connection" feature | admin only, rate limited, stored secrets are only sent to the stored host, other hosts must resolve to public addresses (SSRF guard, re-checked at connect time) |
| Browser attacks | Content-Security-Policy and security headers from the console and API, bearer tokens instead of cookies (no CSRF), no wildcard CORS |
| Network attackers | all traffic through the TLS proxy; Postgres and Redis are not published and sit on a network without outbound routes |
| Container escape / supply chain | non-root service users, read-only root filesystems, dropped capabilities, pinned base images and Python lock file, `pip-audit` and `npm audit` in CI |

### Known limits (read these)

* **Console dependencies.** `npm audit --omit=dev` is clean as of the upgrade to Next.js 15.5.x (the earlier Next.js 14.2.35 had
  critical advisories, including remote code execution on Windows-hosted servers, which is why it was upgraded). PostCSS is pinned
  through the `overrides` section of `frontend/package.json`. The audit runs in CI on every change and new advisories appear over
  time, so keep it green; it is not a guarantee against unknown flaws.
* The session token lives in browser storage, so a script-injection bug in the console would expose it. The CSP allows inline
  scripts because of how Next.js bootstraps pages.
* Anyone who can read the database **and** `PHANTOM_ENCRYPTION_KEY` can read all stored secrets; keep them in different places.
* Rate limits and lockout counters are kept in process memory unless `PHANTOM_RATELIMIT_REDIS_URL` is set, so they reset
  on restart.
* The audit log lives in the same database as everything else; an administrator with database access can alter it. Ship logs
  elsewhere if you need tamper evidence.
* Model confidence is self-reported. Do not raise AI autonomy above `recommend_only` without measuring accuracy.
* Alert data sent to OpenRouter and the chosen model leaves your network (redacted unless `PHANTOM_AI_SEND_RAW_PAYLOAD=true`).
* The Wazuh active-response scripts run as root/SYSTEM on agents. Review them before deploying; the Windows script was never executed in development.

## Secrets handling

* Never commit `.env`, `.phantom_dev_secrets`, `.phantom_dev_key`, database files, backups or bootstrap-password files (all git-ignored).
  `python scripts/gen_env.py` writes `.env` with mode 0600.
* Prefer environment variables or the encrypted Configuration page for integration keys; never put them in playbooks, tickets or chat.
* Use least-privilege credentials for every integration: a Wazuh API user limited to `active-response:command`, an Okta token with only
  the user-lifecycle permissions you need (an admin role limited to a test group first), a Jira user limited to one project, read-only
  threat-intel keys.
* Compose passes secrets as container environment variables, so anyone who can run `docker inspect` on the host can read them. Restrict
  the Docker socket.
* The bootstrap admin password is either from `PHANTOM_BOOTSTRAP_ADMIN_PASSWORD` or generated once into a 0600 file on a volume; the log
  only names the file. Delete it after the first sign-in.
* Backups contain password hashes and encrypted secrets, not the encryption key. Encrypt them off-host and store the key separately.

## Rotating secrets

| Secret | How |
|---|---|
| **Encryption key** (`PHANTOM_ENCRYPTION_KEY`) | 1) Back up the database and the old key. 2) Generate a new key (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`). 3) In `.env` set `PHANTOM_ENCRYPTION_KEY=<new>` and `PHANTOM_ENCRYPTION_KEYS=<new>,<old>` (the first key encrypts, every listed key decrypts). 4) `docker compose up -d`. On start the API re-encrypts every stored secret and MFA seed under the new key and logs `Encryption at rest: {... 'rotated': N ...}`; `undecryptable` must be 0. 5) Check that the Configuration page still shows your integrations as configured and that MFA sign-in works. 6) Remove `PHANTOM_ENCRYPTION_KEYS` (leave `PHANTOM_ENCRYPTION_KEY=<new>`) and restart. Backups taken before the rotation need the old key to be readable: keep it until those backups expire. |
| **JWT secret** (`PHANTOM_JWT_SECRET`) | Replace it and restart; every session ends and everyone signs in again. There is no overlap period. |
| **Ingest token** | Create a new token for the sender on the Accounts page, update the sender, then revoke the old one. A legacy `PHANTOM_INGEST_TOKEN` is rotated by changing the variable and the sender. |
| **Service-account (agent) API key** | Accounts page, "rotate API key"; the new key is shown once and the old one stops working. |
| **User password / MFA** | An admin can reset a password (the user must change it at next sign-in) or flag an account as compromised; MFA can be disabled by the user (with a code) and re-enrolled. |
| **Postgres / Redis passwords** | Change `POSTGRES_PASSWORD`/`REDIS_PASSWORD` in `.env`. Redis picks the new password up on restart. For Postgres also run `ALTER USER phantom PASSWORD '...'` inside the container, because the variable only applies to a new data directory (`docker compose exec db psql -U phantom -c "ALTER USER phantom PASSWORD '<new>'"`), then restart the stack. |
| **Integration keys** (VirusTotal, Okta, Jira, ...) | Create the new key at the vendor, save it on the Configuration page (or `.env`), test the connection, then revoke the old key at the vendor. |

## Hardening checklist

- [ ] `PHANTOM_ENV=production` (compose default), strong `PHANTOM_JWT_SECRET`, `PHANTOM_ENCRYPTION_KEY` generated and stored in a password manager
- [ ] Served only over HTTPS with a real certificate (`PHANTOM_DOMAIN`); no published ports other than the proxy's
- [ ] Docker host patched, Docker socket restricted, host firewall allows only 80/443 (and your Wazuh manager's outbound access)
- [ ] First admin password changed, bootstrap password file deleted, MFA enabled for every human account, `PHANTOM_REQUIRE_MFA_FOR_ADMIN=true`
- [ ] A second admin account with MFA exists; analysts have the lowest role they need; auditors use the read-only role
- [ ] One ingest token per sender, none shared; the legacy `PHANTOM_INGEST_TOKEN` empty
- [ ] Webhook access restricted to the SIEM's address in the proxy or the host firewall where possible
- [ ] `PHANTOM_TRUSTED_PROXIES` correct for your proxy chain (so rate limits see real client addresses)
- [ ] Protected hosts, users and IPs listed before HOTL is ever enabled; HOTL stays off until a lab test passed
- [ ] `WAZUH_CA_BUNDLE` set (verification on) instead of `WAZUH_VERIFY_TLS=false`
- [ ] Allow-list file installed on every Wazuh agent that runs the response scripts (your jump host, DNS, domain controllers, the SOAR server)
- [ ] AI triage: off unless needed; `recommend_only`; raw payload sending off; a spending limit set at OpenRouter
- [ ] Backups running, copied off-host, encrypted there, and a restore test done in the last quarter (`backup verify`)
- [ ] CI green (`pip-audit`, `npm audit`, tests); no open advisories from `npm audit --omit=dev`
- [ ] Logs reviewed for `Insecure configuration`, `cannot be decrypted` and failed-login bursts


## Agent API key lifetime

Service-account (AI agent) keys now expire after **90 days** unless an expiry was given when the key was created.
Set `PHANTOM_AGENT_KEY_DEFAULT_DAYS` to change the default (`0` = no expiry). An expired key is refused with 401 until
it is rotated with a new expiry; rotating without a body keeps the previous expiry. Keys created before this default
existed are not changed.
