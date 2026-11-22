# Deployment guide (Docker Compose)

This is the one supported way to run Phantom SOAR as a service. For development on your own machine see
the README ("Local development"). Nothing here has been run on your server by the authors; follow
`LIVE_CHECKLIST.md` for the first start and keep simulation mode on (a hard stop for every response action, even with credentials saved) until you have worked through it.

## 1. First start

```bash
python scripts/gen_env.py            # creates .env (mode 0600) with generated secrets
docker compose up -d --build --wait  # builds the images and waits until every health check passes
docker compose exec backend cat /app/run/bootstrap_admin_password.txt   # one-time admin password
```

Open `https://localhost`. With the default `PHANTOM_DOMAIN=localhost` the certificate comes from Caddy's
internal CA, so the browser warns until you trust it (section 3). Sign in as `admin` (or the name in
`PHANTOM_BOOTSTRAP_ADMIN_USERNAME`) with the one-time password, change it when asked, delete the file
(`docker compose exec backend rm /app/run/bootstrap_admin_password.txt`) and enable MFA for the account.
If you set `PHANTOM_BOOTSTRAP_ADMIN_PASSWORD` in `.env` before the first start, that password is used and no
file is written. The first-start password is only read when the account is created; changing the variable later
does not change an existing account.

Required values in `.env` (compose refuses to start without them): `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
`PHANTOM_JWT_SECRET` (at least 32 characters), `PHANTOM_ENCRYPTION_KEY` (a Fernet key). The API in
production mode (`PHANTOM_ENV=production`, the compose default) additionally refuses to start with a weak JWT
secret, a missing or invalid encryption key, or simulation mode ON next to configured real connectors
(unless `PHANTOM_SIMULATION_CONFIRMED_IN_PRODUCTION=true`). Every variable is documented in `.env.example`.

How settings are resolved: the database holds only values saved on the Configuration page; for everything else the
environment variable is read at run time and then the built-in default. A value saved in the console wins over the
environment, and a database created by an older version may hold frozen leftovers (see the README, "Upgrading an
existing database"). HOTL is enforced at run time: `PHANTOM_HOTL_ENABLED=true` is ignored, and a warning logged, until
protected hosts/IPs and protected users are listed.

**Back up `PHANTOM_ENCRYPTION_KEY` separately from the database backups.** Integration secrets and MFA seeds
in the database are encrypted with it; without the key they cannot be read.

## 2. What runs

| Service | Image | Published | Notes |
|---|---|---|---|
| `proxy` | `caddy:2.11-alpine` | `${PHANTOM_PUBLISH_HOST:-127.0.0.1}:80` and `:443` | TLS, one origin, security headers, 2 MB request limit. Only published service. Runs as root inside the container with all capabilities dropped except `NET_BIND_SERVICE`. |
| `frontend` | built from `frontend/Dockerfile` (Node 22) | none | Next.js standalone server, runs as `node`. |
| `backend` | built from `backend/Dockerfile` (Python 3.12) | none | FastAPI, one uvicorn process, runs as uid 10001. Applies database migrations at start-up. |
| `celery_worker` | same image as `backend` | none | Background jobs and the embedded Celery beat scheduler (`-B`). |
| `db` | `postgres:16.10-alpine` | none | Internal network only. |
| `redis` | `redis:7.4-alpine` | none | Internal network only, password protected, append-only persistence. |
| `backup` | built from `deploy/backup` | none | Only with `--profile backup`. |

Hardening applied in `docker-compose.yml`: read-only root filesystems (writable: named volumes, `/tmp` tmpfs),
`no-new-privileges`, all capabilities dropped (only what the Postgres/Redis/Caddy entrypoints need is added back),
memory/CPU/process limits, health checks, pinned image tags, and two networks: `data` (internal, no route out)
for Postgres/Redis/backup, and `edge` for the proxy, console and the app services that need to call vendor APIs.
These settings were written for a normal Linux Docker Engine; if your platform rejects one, loosen it in the
compose file rather than removing the others. The image tags are version-pinned, not digest-pinned; pin digests
if your policy requires it.

**One scheduler only.** The `celery_worker` service runs `celery ... worker -B`. Only one container may run with
`-B`; two schedulers would queue every periodic task twice. To add more workers, add a second service without
`-B` and `--schedule`.

**Migrations run once per start, not concurrently.** The `backend` container applies Alembic migrations in its
start-up hook under a Postgres advisory lock. The worker `depends_on` the backend being healthy, and the backend
only becomes healthy after start-up finished, so the worker never sees an old schema. Manual control:

```bash
docker compose exec backend python -m backend.db_migrate current   # applied revision
docker compose exec backend python -m backend.db_migrate check     # exit 1 when not at head
docker compose exec backend python -m backend.db_migrate upgrade   # idempotent
```

## 3. TLS and the domain

* **Real deployment.** Point a DNS name at the server, open ports 80 and 443 to the internet (Let's Encrypt
  validates over them), and set in `.env`:
  ```
  PHANTOM_DOMAIN=soar.example.org
  PHANTOM_PUBLISH_HOST=0.0.0.0
  ```
  then `docker compose up -d`. Caddy obtains and renews the certificate, redirects HTTP to HTTPS and sends
  `Strict-Transport-Security`. Certificates and the ACME account are kept in the `caddy_data` volume; do not
  delete that volume casually (Let's Encrypt rate limits). Set `PHANTOM_BEHIND_TLS=true` if you also want the
  API itself to send HSTS.
* **Localhost / lab.** `PHANTOM_DOMAIN=localhost` uses Caddy's internal CA. To stop the browser warning, export
  its root certificate and trust it in your OS or browser:
  ```bash
  docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./caddy-local-root.crt
  ```
  Only do this on a machine you control. Never trust it on a shared machine, and delete the volume if the file
  is ever shared.
* **Your own certificate / another proxy.** Replace `deploy/caddy/Caddyfile` (Caddy supports `tls cert key`),
  or put your own load balancer in front of the `proxy` service. If you terminate TLS elsewhere, add the proxy's
  address to `PHANTOM_TRUSTED_PROXIES` so rate limits and audit entries see the real client address.
* **Restricting who may post webhooks.** The Caddyfile contains a commented `remote_ip` example for allowing
  only your Wazuh manager. It only works as intended on a Linux Docker host (Docker Desktop hides client
  addresses). The webhook endpoints are also protected by per-sender ingest tokens and a per-address rate limit.

The console and the API share one origin, so `NEXT_PUBLIC_API_URL` stays empty (the browser calls `/api` on its
own origin) and no CORS entry is needed. `NEXT_PUBLIC_API_URL` is a **build-time** argument of the frontend image:
after changing it run `docker compose build frontend && docker compose up -d`.

## 4. Sending alerts to the webhook

Create one ingest token per sender (Accounts page, or `POST /api/ingest-tokens` as an admin; the plaintext is shown
once). A sender posts the alert as JSON:

```bash
curl -sS -X POST https://soar.example.org/api/webhooks/wazuh \
  -H "Content-Type: application/json" -H "X-Phantom-Ingest-Token: $TOKEN" \
  -d '{"rule":{"id":"5710","level":5,"description":"test"},"agent":{"id":"001","name":"lab-host"},"data":{"srcip":"203.0.113.9"}}'
```

Endpoints: `/api/webhooks/wazuh`, `/api/webhooks/edr`, `/api/webhooks/xdr`; bodies over 1 MiB are rejected. The repository
ships a Wazuh-side forwarder: `wazuh/manager/custom-phantom` plus the `<integration>` block in
`wazuh/ossec-manager-snippets.xml` (install it on the Wazuh manager, put your ingest token in `<api_key>`). Any other tool
that can POST the alert JSON with the token header also works. The other scripts in `wazuh/` are the response
(active response) side.

## 5. Backups and restore

Start the backup job (a dump every `BACKUP_INTERVAL_SECONDS`, default daily, keeping the newest `BACKUP_KEEP`, default 14):

```bash
docker compose --profile backup up -d backup
docker compose --profile backup run --rm backup once      # take one now
docker compose --profile backup run --rm backup list
```

Dumps are `pg_dump` custom-format files with a `.sha256` file, written under a temporary name and checked with
`pg_restore --list` before they get their final name. If the reports directory has files, a `phantom_reports_*.tar.gz`
is written next to each dump (the PDFs can also be regenerated from the database, but keep them if they are evidence).
By default they go to the `backup_data` Docker volume, which lives on the same disk as the database: **copy them
elsewhere**. To write to a host directory instead, set `PHANTOM_BACKUP_DIR=/mnt/backups/phantom` and make it writable
for uid 70 (`sudo chown 70:70 /mnt/backups/phantom`). Encrypt backups when you copy them off the host (for example
`age` or `gpg`); they contain password hashes and encrypted (not plaintext) secrets, and the encryption key is
**not** in them.

**Test a restore regularly (does not touch the live database):**

```bash
docker compose --profile backup run --rm backup verify                       # newest dump
docker compose --profile backup run --rm backup verify phantom_soar_20261118T030000Z.dump
```

It verifies the checksum, restores into a scratch database `<name>_restore_check`, checks that tables and an
Alembic revision exist, prints `RESTORE CHECK OK: tables=... alembic_revision=... users=... alerts=...`, and drops the
scratch database again.

**Restore over the live database** (destructive; stop the writers first):

```bash
docker compose stop backend celery_worker
docker compose --profile backup run --rm -e BACKUP_CONFIRM_RESTORE=phantom_soar backup restore phantom_soar_20261118T030000Z.dump
docker compose up -d
```

`BACKUP_CONFIRM_RESTORE` must equal the database name or the command refuses. The restore runs in one transaction
(`--clean --if-exists`), so a failure leaves the previous data in place. Restore the reports archive (only if you need the old PDFs) into the reports volume; the volume names carry the
project prefix, check them with `docker volume ls`:
`docker run --rm -v phantom-soar_backup_data:/b:ro -v phantom-soar_reports_data:/r alpine:3.22 sh -c 'tar -xzf /b/phantom_reports_<stamp>.tar.gz -C /r && chown -R 10001:10001 /r'`.
After restoring onto a **new** host, copy the same
`PHANTOM_ENCRYPTION_KEY` (and `PHANTOM_JWT_SECRET` if you want sessions to continue) into its `.env` first.

## 6. Upgrading and rolling back

```bash
docker compose --profile backup run --rm backup once     # 1. a fresh dump
git pull                                                  # 2. new code
docker compose up -d --build --wait                       # 3. rebuild; migrations run at start-up
docker compose exec backend python -m backend.db_migrate check
```

To roll back: stop the stack, check out the previous commit, restore the dump taken in step 1 (section 5), then
`docker compose up -d --build`. Migrations are not guaranteed to be reversible, so the dump is the rollback.

## 7. Plain local development with Docker (no proxy, no TLS)

```bash
cp docker-compose.override.example.yml docker-compose.override.yml
docker compose up -d --build --wait      # console http://localhost:3000, API http://localhost:8000
```

The override disables the proxy, publishes the backend and frontend on loopback only and builds the frontend with
`NEXT_PUBLIC_API_URL=http://localhost:8000`. Delete the override file to go back to the proxied setup. For
non-Docker development use `scripts/dev.sh` (Linux/macOS) or `start_all.bat` (Windows).

## 8. Mounting a CA certificate for the Wazuh API

`WAZUH_CA_BUNDLE` is a path inside the backend container. Put the PEM in `deploy/certs/` (git-ignored) and add to a
`docker-compose.override.yml`:

```yaml
services:
  backend:
    volumes: ["./deploy/certs/wazuh-ca.pem:/app/certs/wazuh-ca.pem:ro"]
  celery_worker:
    volumes: ["./deploy/certs/wazuh-ca.pem:/app/certs/wazuh-ca.pem:ro"]
```

and set `WAZUH_CA_BUNDLE=/app/certs/wazuh-ca.pem` in `.env`.

## 9. Troubleshooting

* `required variable ... is missing a value`: a REQUIRED value in `.env` is empty. Run `python scripts/gen_env.py` for a new `.env`.
* Backend exits with `Insecure configuration`: the JWT secret is shorter than 32 characters or the encryption key is missing or not a valid Fernet key.
* Backend exits with `PHANTOM_ENV=production with simulation mode ON while real connectors are configured`: real credentials or threat-intelligence keys are saved while simulation mode is on. Environment variables are read at start-up, so restart after changing `.env`. Either set `PHANTOM_SIMULATION_MODE=false` after completing `LIVE_CHECKLIST.md` (this has no effect when the console holds its own saved `simulation_mode` value, because the console wins), or set `PHANTOM_SIMULATION_CONFIRMED_IN_PRODUCTION=true` if simulation really is what you want. With simulation on, no response action is sent anywhere even though credentials are saved; to act for real you must turn simulation off.
* Port 80 or 443 is in use: stop the other service, or set `PHANTOM_HTTP_PORT`/`PHANTOM_HTTPS_PORT` for a local test (the HTTP-to-HTTPS redirect then points at the wrong port; use the HTTPS URL directly).
* `docker compose logs backend celery_worker proxy` shows the start-up messages. The one-time admin password path is logged, the password itself never is.

## Upgrading a database created before environment variables applied after first boot

Earlier releases wrote the default (or the environment value present at first start) of about eleven settings into
the database on first boot, where it then overrode the environment forever. A fresh database no longer does this, but an
existing one still holds those rows, so changing e.g. `PHANTOM_SIMULATION_MODE` or `PHANTOM_AI_ENABLED` can appear to do
nothing. Clear them once, then restart: the exact `UPDATE system_configs ...` statement and the list of keys are in the
README section "Upgrading an existing database". Text fields can also be emptied in the console; on/off switches cannot,
so use the SQL.
