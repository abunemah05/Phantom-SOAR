# Architecture

This document describes what the code on this branch does. Where behaviour depends on configuration, the
setting is named. Nothing here has been verified against live vendor systems (see `LIVE_CHECKLIST.md`).

## 1. Components

```
 Wazuh manager / EDR / XDR            analyst browser
        |  POST JSON + ingest token         |  HTTPS
        v                                   v
   +-----------------------------------------------+
   |  proxy (Caddy)  one origin, TLS, headers      |
   +-----------------------------------------------+
        | /api/*                    | everything else
        v                           v
   backend (FastAPI)           frontend (Next.js)
     |        |  ^
     |        |  +-- queue ----------+
     |        v                      |
     |     Redis (broker) ---> celery_worker (+ beat)
     v                                  |
   PostgreSQL 16 <----------------------+
                                        |
                  outbound HTTPS only:  v
        VirusTotal, AbuseIPDB, OTX, ThreatFox, NVD, OpenRouter (AI),
        Wazuh manager API, Okta, Jira, Slack
```

* **Backend** (`backend/`): FastAPI app under `/api`. Routers: `auth`, `users`, `alerts`, `playbooks`, `configuration`,
  `logs`, `reports`, `ingest-tokens`, `agent` (AI triage and agent API), `webhooks`, `demo`. SQLAlchemy models, Alembic
  migrations (`backend/alembic/`, applied at start-up under a lock; `python -m backend.db_migrate`).
* **Worker** (`backend/celery_app.py`): Celery with Redis as broker. Tasks: `enrich_and_process_alert`,
  `re_enrich_iocs`, `process_alert`, and the periodic `maintenance` task (scheduled by the embedded beat of the one
  worker container). Tasks are written to be safe to run twice. If the broker is unreachable the webhook processes the
  alert inside the request instead.
* **Frontend** (`frontend/`): Next.js 15 (App Router, standalone build), React 18, TypeScript, Tailwind. Pages:
  Dashboard, Alerts (with the Investigate drawer), AI Agent, Playbooks, Logs, Reports, Configuration, Accounts, Security
  (MFA), Login. The session token is kept in browser storage and sent as a Bearer token.
* **Database**: PostgreSQL 16 in Docker; SQLite for local development and the test suite.
* **Proxy** (`deploy/caddy/Caddyfile`): TLS and a single origin; hides `/docs`, `/redoc` and `/openapi.json`.

Tables: `users`, `system_configs`, `alerts`, `ioc_artifacts`, `playbooks`, `playbook_executions`, `containment_actions`,
`incident_reports`, `analyst_action_logs`, `system_logs`, `agent_proposals`, `ingest_tokens`, `revoked_tokens`,
`service_account_policies`, `used_totp_codes` (15, plus `alembic_version`).

## 2. Life of an alert

1. A sender POSTs JSON to `/api/webhooks/wazuh`, `/edr` or `/xdr` with an ingest token (`X-Phantom-Ingest-Token`). Tokens
   are per sender, stored only as hashes, revocable and optionally expiring; a legacy shared token from
   `PHANTOM_INGEST_TOKEN` is honoured only when it is at least 32 characters. Bodies over 1 MiB get HTTP 413; requests
   are rate limited per client address and failed tokens are throttled.
2. The alert is stored (status `New`) with its raw payload. Severity comes from `rule.level` for Wazuh and from the
   payload's `severity` field for EDR/XDR. Up to 25 indicators (IPs, hashes, URLs, domains) are extracted with regular
   expressions and stored; further ones are logged as dropped.
3. A worker (or the request itself, when no broker is reachable) enriches the indicators and then routes the alert.
   Enrichment asks the configured providers: VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox, and NVD for CVE data.
   Provider limits are honoured (`rate_limited` results are retried later); private addresses are never sent out;
   a provider without a key reports `not_configured`. With no keys an indicator stays `Unknown` (score 0). In
   simulation mode only, a small built-in table of lab indicators gets fixture verdicts, labelled as such.
4. A `Malicious` verdict (backed by live provider data, or by a lab fixture while simulation mode is on) raises severity
   by at most one step, never above High; `Unknown` never escalates.
5. **Routing** (`engine/runner.py`). The runner picks a playbook (MITRE id, rule description/groups, and keywords as a
   weaker signal) and then decides:
   * **HOTL (autonomous)** only if all hold: the global switch `hotl_enabled` is on (default **off**), the matched
     playbook is a HOTL playbook chosen by a strong signal, and there is real evidence: a `Malicious` indicator backed
     by live provider data. Telemetry severity alone is never evidence.
   * Otherwise **HITL**: status `Triaged`, nothing runs until an analyst approves.
6. Every playbook step passes `policy.evaluate_action` first, then `actions.execute_action`, and every outcome is
   stored as a containment action with its real mode: `live`, `simulated`, `skipped`, `blocked` or `failed`.
7. Alert status afterwards: `Contained` only if at least one **live** action succeeded; `Simulated` when only
   simulated actions ran (nothing is contained); `Triaged` when waiting for an analyst. The alert is claimed with an
   atomic update and a lease so that a second worker or a redelivered task cannot run it twice. Mean time to respond
   is real elapsed time. An incident PDF can be generated per alert (ReportLab); an analyst-activity PDF is available
   on the Reports page.

## 3. Guardrails

* **Simulation mode** (default on) is a hard stop: no response action is sent to Wazuh, Okta, Jira or Slack, even when
  credentials are saved (`_dispatch` in `engine/actions.py`); each is recorded as a clearly labelled `Simulated` action. Read-only
  threat-intel lookups are unaffected. With simulation off, a connector with credentials acts for real and one without
  records `Skipped`. A simulated action is not counted as containment, and repeating the run after simulation is turned off
  performs the action for real. The demo seeder only works in simulation mode.
* **Policy** (`engine/policy.py`): automated actors (playbooks, the AI agent) can never touch protected hosts, users
  or IPs; analysts can, except for the automatically protected entries (the Wazuh manager, loopback, this server and
  its default gateway), which no actor may isolate or block. Loopback/reserved addresses are never blocked. Actions
  carry per-action parameter validation. Agent actions additionally need `confidence >= agent_min_confidence`
  (default 0.85) and the configured autonomy (`recommend_only` default, `low_impact`, `policy`).
* **HOTL switch** cannot be enabled until protected users and hosts/IPs (or the Wazuh manager) are configured; the
  API answers 409 with the list of blockers.
  The requirement is also enforced at run time (`integration_config.hotl_effective`): a switch set from the environment is
  ignored, with a logged warning, until the protected lists exist. Protected host and user entries match by short name in
  both directions. Automated actors may only act through the Wazuh agent that raised the alert, an unattended HOTL block
  targets only IPs with a `Malicious` verdict, and an analyst-approved run keeps every IP that is not clean.
* **Production start-up checks**: weak JWT secret, missing/invalid encryption key, or simulation mode on next to
  real connectors stop the API from starting.

## 4. Response actions

The catalog (`engine/actions.py`) has 12 actions:

| Action | Connector | Mechanism |
|---|---|---|
| `isolate_endpoint`, `unisolate_endpoint`, `terminate_process`, `quarantine_file` | `edr` | Wazuh manager API `PUT /active-response` calling the `phantom-*` scripts on the agent |
| `block_ip`, `unblock_ip`, `apply_rate_limit` | `firewall` | the same Wazuh active-response API (`phantom-block-ip`, `phantom-unblock-ip`, `phantom-rate-limit`) |
| `disable_account`, `revoke_user_sessions`, `force_password_reset` | `iam` | Okta API |
| `create_ticket` | `itsm` | Jira REST API (or a Jira automation webhook) |
| `send_notification` | `itsm` | Slack incoming webhook |

Wazuh stock only provides some commands; the `phantom-*` scripts in `wazuh/` must be installed on each agent that should
respond (see `wazuh/README.md`; the Windows script was not executed during development). The manager API credentials,
CA bundle and agent lists are settings (`WAZUH_*`). Requests never omit `agents_list` and never target agent `000`.
Connector calls time out after 8 seconds (4 to connect) and retry transient failures a bounded number of times with
backoff; requests that could act twice are retried only when they cannot have been processed (connect errors, 429/503 with
`Retry-After`).

## 5. Built-in AI triage

Off by default (`PHANTOM_AI_ENABLED=false`). When enabled with an OpenRouter key, an analyst (or, if
`PHANTOM_AI_AUTO_TRIAGE=true`, the pipeline after enrichment) can ask a model for a proposal for one alert
(`POST /api/agent/triage/{alert_id}`). The flow (`engine/ai_triage.py`, `integrations/llm.py`):

1. A redacted context is built (entities, indicators with verdicts, MITRE mapping, playbook, what was done). The raw
   payload is included only when `PHANTOM_AI_SEND_RAW_PAYLOAD=true`, and is masked even then. A local per-minute call
   limit applies.
2. A fixed system prompt tells the model it has no tools and that alert text is untrusted data inside random-nonce
   markers; alert text never enters the system prompt.
3. The reply must be strict JSON that validates against a schema (verdict, confidence 0..1, at most 5 catalog
   actions). Anything else becomes a proposal with verdict `unknown` and status `no_action`.
4. Each proposed action goes through the same policy check with actor `agent`. With the default autonomy
   `recommend_only` every proposal waits for a human (`pending_approval`); a human approves or rejects it
   (`/api/agent/proposals/{id}/approve|reject`), and approval re-checks every action as an analyst.
5. External agents can use the same gate with a service-account API key (`X-Phantom-Agent-Key`):
   `GET /api/agent/queue`, `GET /api/agent/alerts/{id}`, `GET /api/agent/actions`, `POST /api/agent/alerts/{id}/proposals`.

Model confidence is self-reported and not calibrated; keep autonomy on `recommend_only` until you have measured the
accuracy yourself. Data sent to the model leaves your network.

## 6. Security model (summary; details in `SECURITY.md`)

* People: username and password (Argon2id; 15 characters minimum, 8 with MFA), JWT (HS256) sessions, optional TOTP MFA
  (mandatory for admins with `PHANTOM_REQUIRE_MFA_FOR_ADMIN`), roles Admin / Security Engineer / SOC Analyst / SOC Auditor
  (read-only), role re-read from the database on every request, logout revocation stored in the database, lockout and
  per-address rate limits on sign-in.
* Machines: per-sender ingest tokens (webhooks) and service-account API keys (agent API).
* Secrets: integration secrets and MFA seeds are encrypted in the database (Fernet, `PHANTOM_ENCRYPTION_KEY`) and
  never returned by the API; the console only shows masked previews.
* Outbound connection tests to arbitrary URLs use an SSRF guard that connects only to public addresses.
* Destructive admin operations (purging alerts) need a one-time confirmation token; audit-log retention has a minimum.

## 7. Repository map

```
backend/            FastAPI app, engine/ (runner, policy, actions, ingest, ai_triage, reporter), integrations/, alembic/, tests/
frontend/           Next.js console
wazuh/              Wazuh active-response scripts, installers and manager snippets
deploy/             Caddy reverse proxy config, database backup job
scripts/            dev launchers, .env generator, smoke test, docs/env consistency check
docs/               this file and DEPLOYMENT.md
docker-compose.yml  the stack;  docker-compose.override.example.yml  plain local development
.github/workflows/  CI
```
