# Phantom SOAR

Phantom SOAR receives security alerts (Wazuh, EDR and XDR webhooks), enriches their indicators with threat
intelligence, matches a response playbook, and either waits for an analyst to approve the response or, under strict
conditions, runs it automatically. An optional AI triage step can propose a verdict and actions, which a human approves.
Everything an automated actor does passes one policy check and is recorded with whether it was real, simulated, skipped,
blocked or failed.

It started as a university graduation project and is developed in this repository. **Treat it as a lab platform until
you have worked through [`LIVE_CHECKLIST.md`](LIVE_CHECKLIST.md) yourself.** The code and its several hundred automated
tests mock every vendor; the authors have not tested it against live Wazuh, Okta, Jira, Slack or the threat-intel
providers, and it has not had an independent security audit.

## What it does

* **Ingestion**: `POST /api/webhooks/wazuh`, `/edr`, `/xdr` with a per-sender ingest token. Indicators (IPs, hashes, URLs,
  domains, at most 25 per alert) are extracted and stored.
* **Enrichment**: VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox (indicators) and NVD (CVE details). A provider without a
  key reports `not_configured`; with no keys indicators stay `Unknown`. Rate limits are respected and retried.
* **Playbooks**: 13 templates (ransomware, brute force, phishing, privilege escalation, web shell, exfiltration, lateral
  movement, DDoS, credential dumping, SQL injection, supply chain, insider threat, reconnaissance), editable in the console.
* **Response actions** (12): isolate/unisolate endpoint, terminate process, quarantine file, block/unblock IP, rate limit
  (all through Wazuh active response), disable account, revoke sessions, force password reset (Okta), create ticket (Jira),
  send notification (Slack).
* **Guardrails**: protected hosts/users/IPs, simulation mode, an HOTL master switch that is **off by default**, MFA,
  roles, audit log, encrypted secrets.
* **AI triage (optional, off by default)**: OpenRouter-backed proposals, validated and policy-checked, waiting for a
  human unless you change the autonomy setting. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
* **Console**: Dashboard, Alerts and Cases (Investigate drawer, approve/dismiss), AI Agent, Playbooks, Logs, Reports
  (incident PDF per alert, analyst-activity PDF), Configuration, Accounts, My Security.

What it is **not**: there is no built-in alert source (you need Wazuh or another sender that posts JSON), no shipped
Wazuh-side forwarder, no benchmark of throughput or response time (mean time to respond is the real elapsed time of each
alert), and no high-availability setup (one API process, one worker with the scheduler).

## Simulation and live mode

With **simulation mode on (the default)**, a connector without credentials records a clearly labelled `Simulated`
action; nothing reaches a real system. A simulated action never counts as containment: an alert whose actions were all
simulated gets status `Simulated`, not `Contained`, and running it again after the connector is configured performs the
action for real. With simulation off, an unconfigured connector records `Skipped`. The "Generate demo data" button on the
dashboard (admin only) works only in simulation mode and sends lab alerts through the real pipeline.

**Autonomous response (HOTL) is off by default.** It can only be switched on after protected users and hosts/IPs are
configured, and even then a playbook runs without approval only if the playbook is a HOTL playbook chosen by a strong
signal and a `Malicious` indicator is backed by live threat-intel data. Telemetry severity alone is never enough.
Everything else waits in status `Triaged` for an analyst.

**AI agent autonomy defaults to `recommend_only`**: every AI proposal waits for a human to approve it.

## Quick start (Docker Compose)

Requires Docker Engine with the Compose plugin.

```bash
python scripts/gen_env.py                 # creates .env with generated secrets (or: cp .env.example .env and fill it)
docker compose up -d --build --wait       # Postgres, Redis, API, worker, console and the TLS proxy
docker compose exec backend cat /app/run/bootstrap_admin_password.txt   # one-time admin password
```

Open <https://localhost> (a certificate from Caddy's internal CA: the browser warns until you trust it, see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)), sign in as `admin`, change the password, delete the password file and enable
MFA under *My Security*. To use a real DNS name and a Let's Encrypt certificate set `PHANTOM_DOMAIN` and
`PHANTOM_PUBLISH_HOST=0.0.0.0`. Compose refuses to start until `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `PHANTOM_JWT_SECRET`
and `PHANTOM_ENCRYPTION_KEY` are set; the API refuses to start in production without a strong JWT secret and a valid
encryption key. Back the encryption key up separately from database backups.

Only the proxy publishes ports (80 and 443, on `127.0.0.1` unless you change `PHANTOM_PUBLISH_HOST`). Postgres and
Redis are never published. For plain local development without TLS see `docker-compose.override.example.yml`.

### Safe order to make it real

1. Start with simulation **on** and HOTL **off** (the defaults). Click through the demo data, approve one alert, download
   a PDF, enable MFA, create an ingest token and post a test alert with `curl`.
2. List protected hosts, users and IPs on the Configuration page (your Wazuh manager, gateways, DNS, domain controllers,
   break-glass admins; the manager, this server, loopback and the gateway are protected automatically).
3. Add the threat-intel keys one by one and use the Test buttons. Free tiers rate-limit hard.
4. Prepare Wazuh active response on **one lab agent** ([`wazuh/README.md`](wazuh/README.md)), then add the Wazuh API settings, with a CA bundle instead of disabling TLS verification.
5. Add Okta, Jira and Slack, each against a sandbox or test project first.
6. Only then turn simulation mode off (the API refuses to start in production with simulation on next to real credentials),
   send a real low-severity test alert and approve its actions by hand.
7. Enable HOTL last, if at all, and test it with one playbook you trust.

[`LIVE_CHECKLIST.md`](LIVE_CHECKLIST.md) turns this order into a test plan with expected results and rollback steps.

## Wazuh response architecture

Phantom does not run commands on endpoints itself. It calls the **Wazuh manager API** (`PUT /active-response`) naming a
command and one or more agents; the manager tells each agent to run the script. Wazuh ships only a few stock scripts, so
the repository provides the rest in [`wazuh/`](wazuh/): `phantom-isolate-host`, `phantom-unisolate-host`,
`phantom-block-ip`, `phantom-unblock-ip`, `phantom-rate-limit`, `phantom-kill-process`, `phantom-quarantine-file` for Linux
(nftables) and Windows (Windows Firewall, PowerShell 5.1; rate limiting is not supported on Windows). The scripts validate
their input strictly, refuse to touch the manager, loopback and an allow-list, and log every decision. Install them on each
agent that should respond and create a Wazuh API user with the `active-response:command` permission. The Windows scripts
could not be executed during development: dry-run them on a lab agent first.

## Configuration

Settings come from the Configuration page (stored in the database, secrets encrypted) or from environment variables; a value
saved in the console wins. [`.env.example`](.env.example) documents every variable. The most important ones:

| Variable | Required | Meaning |
|---|---|---|
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | compose | passwords of the bundled database and broker |
| `PHANTOM_JWT_SECRET` | production | at least 32 random characters; signs login tokens |
| `PHANTOM_ENCRYPTION_KEY` | production | Fernet key encrypting stored secrets (`PHANTOM_ENCRYPTION_KEYS` for rotation) |
| `PHANTOM_ENV` | no | `development`, `production` (compose default) or `test` |
| `PHANTOM_DOMAIN`, `PHANTOM_PUBLISH_HOST` | no | public name for the TLS certificate; interface to publish on |
| `PHANTOM_BOOTSTRAP_ADMIN_USERNAME`, `PHANTOM_BOOTSTRAP_ADMIN_PASSWORD` | no | first admin; without a password a one-time one is written to a file |
| `PHANTOM_INGEST_TOKEN` | no | legacy shared webhook token (ignored under 32 characters); prefer per-sender tokens |
| `PHANTOM_REQUIRE_MFA_FOR_ADMIN` | no | admins must use MFA |
| `PHANTOM_SIMULATION_MODE` | no | default `true` |
| `PHANTOM_HOTL_ENABLED` | no | default `false` |
| `PHANTOM_PROTECTED_HOSTS`, `PHANTOM_PROTECTED_USERS`, `PHANTOM_PROTECTED_IPS` | no | never touched by automated actions |
| `PHANTOM_AGENT_AUTONOMY`, `PHANTOM_AGENT_MIN_CONFIDENCE` | no | `recommend_only` / 0.85 by default |
| `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `PHANTOM_AI_ENABLED`, `PHANTOM_AI_AUTO_TRIAGE`, `PHANTOM_AI_MAX_ALERTS_PER_MINUTE`, `PHANTOM_AI_SEND_RAW_PAYLOAD` | no | AI triage, all off by default |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `ALIENVAULT_OTX_API_KEY`, `THREATFOX_API_KEY`, `NVD_API_KEY` | no | threat intelligence |
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `WAZUH_VERIFY_TLS`, `WAZUH_CA_BUNDLE` | no | Wazuh manager API |
| `OKTA_DOMAIN`, `OKTA_API_TOKEN` | no | Okta |
| `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`, `SLACK_WEBHOOK_URL` | no | ticketing and notifications |
| `NEXT_PUBLIC_API_URL` | no | **build-time** API URL for the console; empty = same origin (default). Rebuild the frontend after changing it |

## Backups and migrations

* `docker compose --profile backup up -d backup` starts a daily `pg_dump` job with retention; `backup verify` restores the
  newest dump into a scratch database and checks it. Restore instructions and the reports archive are in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Copy backups off the host and test a restore before you rely on them.
* Schema changes are Alembic migrations, applied automatically when the API starts (under a lock, so several processes
  starting together do not race). `python -m backend.db_migrate current|check|upgrade` and `backend/alembic/README.md`
  describe the details.

## Local development (without Docker)

Requires Python 3.12+ and Node.js 20+ (CI uses 22).

```bash
scripts/dev.sh              # Linux/macOS: API on 127.0.0.1:8000 and console on :3000 (Ctrl+C stops both)
start_all.bat               # Windows: checks prerequisites and ports, opens two windows; any key stops both; stop_all.bat cleans up
python -m pytest backend/tests -q        # backend tests (SQLite)
cd frontend && npm ci && npx tsc --noEmit && npm run lint && npm run build
```

The dev scripts bind the API to loopback only, keep random development secrets in `.phantom_dev_secrets` (git-ignored) and
read `.env` if present. Only set `BACKEND_HOST=0.0.0.0` on a trusted lab network: the dev server speaks plain HTTP.

CI (`.github/workflows/ci.yml`) runs ruff, shellcheck, the backend tests on SQLite and on Postgres 16, `pip-audit`, the
frontend typecheck/lint/build/`npm audit`, Docker builds of both images, and a Compose smoke test (HTTPS through the proxy,
webhook ingest, backup and restore check).

## Troubleshooting

* **Windows: `next dev` fails with `EINVAL` / `readlink` errors on `.next`, or builds are flaky.** The project is inside a
  OneDrive (or other cloud-synced) folder; the sync client turns build files into placeholders that Next.js cannot read.
  Move the project to a local folder outside OneDrive (for example `C:\dev\phantom-soar`) and delete `frontend\.next`.
* **`required variable ... is missing a value`**: run `python scripts/gen_env.py`, or fill the REQUIRED values in `.env`.
* **API exits with `Insecure configuration`**: JWT secret under 32 characters, or `PHANTOM_ENCRYPTION_KEY` missing or not a Fernet key.
* **API exits with `... simulation mode ON while real connectors are configured`**: see the safe order above.
* **A secret saved in the console shows as unset after a restart**: the encryption key changed; restore the old
  `PHANTOM_ENCRYPTION_KEY` (or list it in `PHANTOM_ENCRYPTION_KEYS`).
* **Locked out after failed sign-ins**: lockouts are per username and client address and expire on their own (15-minute window);
  another admin can unlock an account on the Accounts page. There is no command-line password reset: keep a second admin
  account (with MFA) and a recent database backup.

## More documentation

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (how it works), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (TLS, backups,
upgrades), [SECURITY.md](SECURITY.md) (reporting, threat model, key rotation, hardening checklist),
[LIVE_CHECKLIST.md](LIVE_CHECKLIST.md) (manual test plan against real systems), [wazuh/README.md](wazuh/README.md),
`backend/alembic/README.md`. Two generated guides ([HTML](Phantom_SOAR_Educational_Guide.html),
[educational PDF](Phantom_SOAR_Educational_Guide.pdf), [architecture PDF](Phantom_SOAR_Master_Architecture_and_AI_Guide.pdf))
are rebuilt with `python build_educational_pdf.py` and `python generate_architecture_pdf.py`.

## License

No license has been chosen yet; see [LICENSE](LICENSE). Until the owner adds one, all rights are reserved.
