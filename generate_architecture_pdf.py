"""Builds Phantom_SOAR_Master_Architecture_and_AI_Guide.pdf.

    python generate_architecture_pdf.py [output_directory]     (needs: pip install reportlab)

The text describes the code in this repository (see also docs/ARCHITECTURE.md). Statements about behaviour were taken from
the source; nothing here claims live testing against vendor systems. Edit the BLOCKS list, then rebuild.
"""
import os
import sys

from guide_render import build_pdf

COVER = {
    "title": "Phantom SOAR: Architecture and AI Triage Guide",
    "subtitle": "How alerts become enriched, policy-checked and (optionally) approved response actions",
    "lines": [
        "This guide describes what the code in this repository does today: the components, the life of an alert, the guardrails "
        "that limit automation, the optional AI triage step and the deployment. It was written from the source. The code and its "
        "automated tests mock every vendor system; nothing here has been verified against live Wazuh, Okta, Jira, Slack or "
        "threat-intelligence services (see LIVE_CHECKLIST.md).",
    ],
    "meta": [
        ("Platform", "Phantom SOAR 2.0 (branch real-soar)"),
        ("Backend", "Python 3.12, FastAPI, SQLAlchemy and Alembic, Celery with Redis"),
        ("Database", "PostgreSQL 16 (Docker); SQLite for development and tests"),
        ("Console", "Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS"),
        ("Edge", "Caddy reverse proxy: one HTTPS origin"),
        ("Author", "Omar Abunemah, Balqa Applied University"),
    ],
}

DIAGRAM_TOPOLOGY = """
   Wazuh / EDR / XDR senders                     analyst browser
            | POST JSON + ingest token                  | HTTPS
            v                                           v
   +--------------------------------------------------------------+
   |  proxy (Caddy): TLS, single origin, security headers         |
   +------------------------------+-------------------------------+
                                  | /api/*              | /  (console)
                                  v                     v
                        backend (FastAPI)          frontend (Next.js)
                          |            |
              SQLAlchemy  |            | enqueue
                          v            v
                  PostgreSQL 16     Redis  --->  celery_worker (+ beat)
                          ^                            |
                          +----------------------------+
                                                       | outbound HTTPS only
                                                       v
   VirusTotal, AbuseIPDB, OTX, ThreatFox, NVD, OpenRouter (AI),
   Wazuh manager API (-> agents), Okta, Jira, Slack
"""

DIAGRAM_ROUTING = """
 alert stored (New) -> indicators extracted (max 25) -> threat-intel enrichment
                                                              |
                                        Malicious verdict? -> severity +1 step (max High)
                                                              v
                                                 playbook matched (MITRE id, rule text, keywords)
                                                              |
    HOTL switch ON  AND  HOTL playbook chosen by a strong signal  AND  live Malicious evidence?
              | yes                                                    | no
              v                                                        v
    steps run through policy + connectors                   status Triaged: waits for an
    (live / simulated / skipped / blocked / failed)         analyst who approves or dismisses it
              |
    Contained (a LIVE action succeeded) | Simulated (only simulated actions) | Triaged / Partial
"""

DIAGRAM_AI = """
 analyst clicks "triage"  (or auto-triage after enrichment, if enabled)
          |
          v
 preconditions: AI enabled, key present, per-minute budget left, alert not busy   (else HTTP 409)
          |
          v
 redacted context (entities, IOC verdicts, MITRE, playbook)  -- raw payload only if explicitly enabled
          |
          v
 fixed system prompt + alert data in random-nonce delimiters  -->  OpenRouter model  (no tools)
          |
          v
 strict JSON, validated (verdict, confidence 0..1, <= 5 catalog actions)  -- invalid => verdict unknown, no_action
          |
          v
 each action: policy.evaluate_action(actor="agent", confidence)  -->  allowed / needs approval / blocked
          |
          +--> default autonomy "recommend_only": status pending_approval, a human approves or rejects
"""

BLOCKS = [
    ("h1", "1. Components"),
    ("code", DIAGRAM_TOPOLOGY),
    ("table", ["Component", "Role", "Notes"], [
        ["`proxy`", "TLS termination, one origin, request size limit, security headers", "Caddy 2. Obtains a Let's Encrypt certificate for a real `PHANTOM_DOMAIN`, an internal-CA certificate for `localhost`. Hides `/docs`, `/redoc`, `/openapi.json`."],
        ["`frontend`", "Analyst console", "Next.js standalone server. Pages: Dashboard, Alerts and Cases, AI Agent, Playbooks, Logs, Reports, Configuration, Accounts, My Security."],
        ["`backend`", "REST API under `/api`", "FastAPI, one uvicorn process. Applies Alembic migrations at start-up under a database lock."],
        ["`celery_worker`", "Background jobs", "Enrichment and routing of alerts, delayed re-enrichment, periodic maintenance (embedded beat; only one scheduler may run)."],
        ["`db`, `redis`", "State and queue", "Not published; on an internal Docker network without outbound routes."],
        ["`backup` (profile)", "Database dumps", "`pg_dump` with retention, checksum, restore check."],
    ], [0.17, 0.30, 0.53]),
    ("p", "If the Redis broker cannot be reached the webhook processes the alert inside the request instead of queueing it. Background tasks are written to be safe to run twice (the alert is claimed with an atomic update and a lease)."),

    ("h1", "2. Life of an alert"),
    ("ul", [
        "**Ingest.** `POST /api/webhooks/wazuh|edr|xdr` with the `X-Phantom-Ingest-Token` header. Tokens are per sender, stored only as hashes, revocable, optionally expiring. A legacy shared token from `PHANTOM_INGEST_TOKEN` is honoured only when it is at least 32 characters. Bodies over 1 MiB get HTTP 413.",
        "**Severity.** Wazuh: from `rule.level`. EDR and XDR: from the payload's `severity` field (Critical, High, Medium, Low; anything else becomes Medium). The sender is trusted for this value, which is why severity alone never triggers autonomous action.",
        "**Indicators.** IPs, hashes, URLs and domains are extracted with regular expressions (defanged forms are understood), de-duplicated and capped at 25 per alert; the rest are logged as dropped.",
        "**Enrichment** (worker). Providers: VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox; NVD for CVE details. See section 4.",
        "**Routing.** A playbook is matched, then the alert is either run autonomously or parked for an analyst (diagram below).",
        "**Result.** Every step is recorded as a containment action with its real mode. An incident PDF can be produced per alert.",
    ]),
    ("code", DIAGRAM_ROUTING),
    ("h2", "Status vocabulary"),
    ("table", ["Status", "Meaning"], [
        ["New", "Stored, not yet processed."],
        ["Processing", "Claimed by a worker (a lease prevents a second run; a stale lease can be reclaimed)."],
        ["Triaged", "Waiting for an analyst to approve or dismiss."],
        ["Contained", "At least one **live** containment action succeeded."],
        ["Simulated", "Only simulated actions ran. Nothing was contained."],
        ["Resolved / Closed / Monitoring", "Set by analysts."],
    ], [0.3, 0.7]),

    ("h1", "3. HOTL, HITL and the guardrails"),
    ("p", "**HOTL** (human on the loop) means the platform acts first and a human reviews afterwards. **HITL** (human in the loop) means nothing runs until a human approves. HOTL is allowed only when all of the following hold:"),
    ("ul", [
        "the global HOTL switch is on (default **off**; it cannot be switched on until protected users and protected hosts or IPs are configured),",
        "the matched playbook is a HOTL playbook and was selected by a strong signal (a MITRE technique id, or the sender's own rule description or groups), never by keywords found only in free-text log fields,",
        "there is real evidence: an indicator whose verdict is `Malicious` and is backed by live provider data (lab fixtures count only while simulation mode is on).",
    ]),
    ("p", "Everything else is HITL. High severity or a high score alone never triggers autonomous containment."),
    ("h2", "Policy engine"),
    ("p", "Every action, whoever asks for it (playbook, AI agent, analyst), goes through `policy.evaluate_action`. Automated actors can never touch protected hosts, users or IPs (an analyst can, and the decision notes it). The Wazuh manager, loopback, this server and its default gateway are protected automatically and no actor, analysts included, may isolate or block them. Loopback and reserved addresses are never blocked. Agent actions need a confidence of at least `agent_min_confidence` (default 0.85) and the configured autonomy: `recommend_only` (default), `low_impact` or `policy`."),
    ("h2", "Simulation mode"),
    ("p", "On by default. A connector without credentials records an action labelled `Simulated`; with simulation off it records `Skipped`. A simulated action never counts as containment, and running the alert again after the connector is configured performs it for real. In production the API refuses to start with simulation on while real credentials are configured, unless `PHANTOM_SIMULATION_CONFIRMED_IN_PRODUCTION=true`."),

    ("h1", "4. Threat intelligence"),
    ("p", "Each provider result carries a status: `live`, `not_found`, `not_configured`, `error`, `rate_limited` (with a retry time), `lab_fixture` (simulation mode only) or `skipped` (private or reserved addresses are never sent to a provider). Only `live` and `lab_fixture` results with a score count as evidence; a rate-limited or missing answer is never treated as clean."),
    ("table", ["Provider", "Score", "Notes"], [
        ["VirusTotal", "Weighted share of engines that flag the indicator, scaled so that the default 10 percent reaches the Malicious score", "Fewer than `VT_MIN_DETECTIONS` weighted detections can never score Malicious. Free tier: 4 requests per minute, 500 per day (configurable)."],
        ["AbuseIPDB", "Its abuse confidence score", "0 for allow-listed IPs. IPs only."],
        ["AlienVault OTX", "20 + 10 per pulse, at most 60", "On its own it can reach Suspicious, never Malicious."],
        ["ThreatFox", "Highest confidence among matching listings", "A listing is never scored Clean."],
        ["NVD", "CVE and CVSS details", "Shown in the alert detail; not part of the verdict."],
    ], [0.17, 0.38, 0.45]),
    ("p", "The consensus threat score is the maximum over evidence-backed providers. Verdicts: Malicious at 70 or more, Suspicious at 30 or more, otherwise Clean; Unknown when no provider returned evidence (thresholds are settings). A Malicious verdict raises the alert's severity by one step, never above High. With no API keys every indicator is Unknown with score 0; there is no offline heuristic or machine-learning scoring."),

    ("h1", "5. Response actions"),
    ("table", ["Action", "Connector", "How it is carried out"], [
        ["`isolate_endpoint`, `unisolate_endpoint`", "edr", "Wazuh manager API `PUT /active-response`, command `phantom-isolate-host` / `phantom-unisolate-host` on the agent"],
        ["`terminate_process`, `quarantine_file`", "edr", "Active-response scripts `phantom-kill-process`, `phantom-quarantine-file`"],
        ["`block_ip`, `unblock_ip`, `apply_rate_limit`", "firewall", "Active-response scripts on the alert's agent or on configured gateway agents (nftables on Linux, Windows Firewall for block; no rate limiting on Windows)"],
        ["`disable_account`, `revoke_user_sessions`, `force_password_reset`", "iam", "Okta API"],
        ["`create_ticket`", "itsm", "Jira REST API or a Jira automation webhook"],
        ["`send_notification`", "itsm", "Slack incoming webhook"],
    ], [0.34, 0.12, 0.54]),
    ("p", "Phantom never runs commands on endpoints itself. It asks the Wazuh manager to tell named agents to run a script. Only some commands are stock Wazuh, so the repository ships the rest in `wazuh/` (Linux and Windows installers, an allow-list, manager snippets). The scripts validate input strictly, refuse to touch the manager, loopback and the allow-list, and log every decision. The request always names `agents_list` and never agent 000. The Windows scripts were not executed during development."),
    ("p", "Connector calls time out after 8 seconds (4 to connect) and retry transient failures a bounded number of times; requests that could act twice are retried only when they cannot have been processed."),

    ("h1", "6. Built-in AI triage (optional)"),
    ("p", "Disabled by default. When `PHANTOM_AI_ENABLED=true` and an OpenRouter key is configured, an analyst (or, with `PHANTOM_AI_AUTO_TRIAGE=true`, the pipeline after enrichment) can request a proposal for one alert. The model never receives secrets, never calls tools and never executes anything: it returns text that is validated and then goes through the same policy engine as every other actor."),
    ("code", DIAGRAM_AI),
    ("ul", [
        "**Data leaves your network**: the redacted context is sent to OpenRouter and the model you choose. `PHANTOM_AI_SEND_RAW_PAYLOAD=true` sends the (masked) raw alert as well.",
        "**Prompt injection**: alert text is attacker-controlled. It is placed only inside delimited data blocks, never in the system prompt, and the answer can only be a proposal. Policy still blocks protected targets.",
        "**Confidence is self-reported** by the model and is not calibrated. Keep autonomy on `recommend_only` until you have measured accuracy.",
        "**Cost control**: a local calls-per-minute limit, request timeouts, one retry and capped output size. Set a spending limit at OpenRouter as well.",
        "**External agents** can use the same gate with a service-account API key (`X-Phantom-Agent-Key`): list the queue, read a redacted alert, read the action catalog, submit a proposal.",
    ]),
    ("table", ["Endpoint", "Who", "Purpose"], [
        ["`GET /api/agent/status`, `/proposals`, `/proposals/{id}`", "any signed-in user", "settings summary (never the key), proposal list and detail"],
        ["`POST /api/agent/triage/{alert_id}`", "responder roles", "run the built-in triage (409 when disabled, no key, rate limited or busy)"],
        ["`POST /api/agent/proposals/{id}/approve`, `/reject`", "human analyst", "decide; a second decision gets 409"],
        ["`GET /api/agent/queue`, `/alerts/{id}`, `/actions`; `POST /api/agent/alerts/{id}/proposals`", "service account (API key)", "external agent interface"],
    ], [0.45, 0.2, 0.35]),

    ("h1", "7. Security design"),
    ("ul", [
        "**People**: Argon2id passwords (15 characters minimum, 8 with MFA), JWT sessions, optional TOTP MFA (mandatory for admins with `PHANTOM_REQUIRE_MFA_FOR_ADMIN`), roles Admin, Security Engineer, SOC Analyst, SOC Auditor (read-only); the role is re-read on every request; logout revocation is stored in the database; failed-login blocking per username-and-address pair, and per-address rate limits.",
        "**Machines**: per-sender ingest tokens and service-account API keys, both stored as hashes.",
        "**Secrets at rest**: integration secrets and MFA seeds are Fernet-encrypted with `PHANTOM_ENCRYPTION_KEY` (rotation with `PHANTOM_ENCRYPTION_KEYS`). The API never returns a stored secret.",
        "**Outbound tests** to a URL that is not the stored one use an SSRF guard that connects only to public addresses.",
        "**Operations**: audit log with a minimum retention; purging all alerts needs a one-time confirmation token; production start-up refuses weak configuration.",
        "**Containers**: non-root users, read-only root filesystems, dropped capabilities, resource limits, pinned images, no published database or broker ports.",
    ]),

    ("h1", "8. Data model"),
    ("p", "Fifteen tables plus `alembic_version`: `users`, `system_configs`, `alerts`, `ioc_artifacts`, `playbooks`, `playbook_executions`, `containment_actions`, `incident_reports`, `analyst_action_logs`, `system_logs`, `agent_proposals`, `ingest_tokens`, `revoked_tokens`, `service_account_policies`, `used_totp_codes`. Thirteen playbook templates are seeded on first start."),

    ("h1", "9. Deployment and operations"),
    ("ul", [
        "`python scripts/gen_env.py` then `docker compose up -d --build --wait`. Required secrets: Postgres and Redis passwords, JWT secret, encryption key.",
        "Backups: `docker compose --profile backup up -d backup`; `backup verify` restores the newest dump into a scratch database and checks it. Copy backups off the host and encrypt them; the encryption key is not inside them.",
        "CI runs ruff, shellcheck, the test suite on SQLite and Postgres 16, `pip-audit`, the frontend typecheck, lint, build and `npm audit`, Docker builds and a Compose smoke test.",
        "Details: `docs/DEPLOYMENT.md`, `SECURITY.md`, `LIVE_CHECKLIST.md`.",
    ]),

    ("h1", "10. Limits"),
    ("ul", [
        "No benchmark has been run: there is no measured response time or throughput; mean time to respond is the real elapsed time of each alert.",
        "No high availability: one API process and one worker with the scheduler.",
        "Alerts must be sent to the webhook by something else; no Wazuh-side forwarder is shipped.",
        "Vendor behaviour (Wazuh active-response request shape for your version, Okta user lookup by name, ThreatFox query types, rate limits) has to be checked against current vendor documentation and your own systems.",
        "The console's dependency audit currently reports advisories for the pinned Next.js 14 line; upgrade before exposing it to untrusted networks.",
    ]),
]


if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    out_file = os.path.join(out_dir, "Phantom_SOAR_Master_Architecture_and_AI_Guide.pdf")
    build_pdf(out_file, COVER, BLOCKS,
              header_left="PHANTOM SOAR: ARCHITECTURE AND AI TRIAGE GUIDE",
              header_right="describes branch real-soar",
              footer_left="Balqa Applied University - Phantom SOAR. Generated by generate_architecture_pdf.py")
    print(f"Wrote {out_file}")
