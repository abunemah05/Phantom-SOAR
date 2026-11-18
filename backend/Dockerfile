# syntax=docker/dockerfile:1
# Phantom SOAR backend image (FastAPI API and Celery worker share it).
# Build context is ./backend; the package is installed at /app/backend so
# "backend.main:app" resolves with PYTHONPATH=/app.
#
# Runs as an unprivileged user and needs no writable root filesystem: compose mounts
# volumes/tmpfs only at /app/backend/reports, /app/run and /tmp.
FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    HOME=/tmp \
    REPORTS_DIR=/app/backend/reports \
    DATABASE_URL=sqlite:////app/data/phantom_soar.db

WORKDIR /app

RUN groupadd --system --gid 10001 phantom \
    && useradd --system --uid 10001 --gid phantom --home-dir /app --no-create-home \
       --shell /usr/sbin/nologin phantom

# Runtime dependencies from the fully pinned lock file (direct and transitive), so two builds
# of the same commit install the same packages. Regenerate backend/requirements.lock whenever
# backend/requirements.txt changes (instructions are at the top of the lock file; CI checks it).
# psycopg2-binary / argon2 / cryptography ship wheels, so no compiler or system packages are needed.
COPY requirements.lock /tmp/requirements.lock
RUN pip install -r /tmp/requirements.lock && rm /tmp/requirements.lock

# Application code stays root-owned (read-only for the service user); only these directories are writable:
#   reports  incident / audit PDFs (a volume in compose)
#   data     SQLite file when DATABASE_URL is not set (not used with the bundled Postgres)
#   run      one-time bootstrap admin password file (a volume in compose)
COPY . /app/backend
RUN mkdir -p /app/backend/reports /app/data /app/run \
    && chown phantom:phantom /app/backend/reports /app/data /app/run \
    && chmod 0750 /app/run

USER phantom

EXPOSE 8000

# One process on purpose: login throttling and a few caches live in process memory. Scale the Celery
# worker, not this service (see docker-compose.yml). Migrations run at start-up under a database lock.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
