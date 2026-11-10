#!/usr/bin/env bash
# Phantom SOAR local development launcher (Linux / macOS equivalent of start_all.bat).
#
#   scripts/dev.sh             backend on :8000 + frontend on :3000
#   scripts/dev.sh backend     backend only
#   scripts/dev.sh frontend    frontend only
#
# Loads .env when present, then fills in development defaults for anything unset.
# Ctrl+C stops both servers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${1:-all}"
case "$MODE" in
  all | backend | frontend) ;;
  *) echo "usage: $0 [all|backend|frontend]" >&2; exit 2 ;;
esac

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"  # 0.0.0.0 to accept webhooks from other machines
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

# KEY=VALUE lines from .env; variables already set in the shell win, empty values
# stay unset. The file is parsed, not executed.
load_env_file() {
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    [[ -z "$value" || -n "${!key:-}" ]] && continue
    if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then
      value="${BASH_REMATCH[1]}"
    fi
    export "$key=$value"
  done < "$1"
}

if [[ -f .env ]]; then
  echo "[dev] loading .env"
  load_env_file .env
fi

# Development defaults for anything still unset.
: "${PHANTOM_ENV:=development}"
: "${PHANTOM_SIMULATION_MODE:=true}"
: "${PHANTOM_INGEST_TOKEN:=dev-ingest-token}"
: "${PHANTOM_CORS_ORIGINS:=http://localhost:${FRONTEND_PORT},http://127.0.0.1:${FRONTEND_PORT}}"
: "${NEXT_PUBLIC_API_URL:=http://localhost:${BACKEND_PORT}}"
export PHANTOM_ENV PHANTOM_SIMULATION_MODE PHANTOM_INGEST_TOKEN PHANTOM_CORS_ORIGINS NEXT_PUBLIC_API_URL

# ----------------------------------------------------------------------------- backend
setup_backend() {
  local venv="$ROOT/.venv" py="$ROOT/.venv/bin/python"
  if [[ ! -x "$py" ]]; then
    echo "[dev] creating virtualenv in .venv"
    if command -v uv > /dev/null 2>&1; then
      uv venv "$venv"
    else
      python3 -m venv "$venv"
    fi
  fi

  # Reinstall only when the requirement files change.
  local stamp="$venv/.phantom-requirements.sha256" want
  want="$(cat backend/requirements.txt backend/requirements-dev.txt | { sha256sum 2> /dev/null || shasum -a 256; } | cut -d' ' -f1)"
  if [[ ! -f "$stamp" || "$(cat "$stamp")" != "$want" ]]; then
    echo "[dev] installing backend dependencies"
    if command -v uv > /dev/null 2>&1; then
      uv pip install --python "$py" -r backend/requirements-dev.txt
    else
      "$py" -m pip install -r backend/requirements-dev.txt
    fi
    echo "$want" > "$stamp"
  fi

  if [[ -z "${PHANTOM_JWT_SECRET:-}" ]]; then
    # Stable for this launch (survives uvicorn --reload); sessions end when dev.sh exits.
    PHANTOM_JWT_SECRET="$("$py" -c 'import secrets; print(secrets.token_urlsafe(48))')"
    export PHANTOM_JWT_SECRET
  fi
}

run_backend() {
  echo "[dev] backend:  http://${BACKEND_HOST}:${BACKEND_PORT}  (docs: /docs)"
  echo "[dev] webhook ingest token: ${PHANTOM_INGEST_TOKEN}"
  if [[ -z "${PHANTOM_BOOTSTRAP_ADMIN_PASSWORD:-}" ]]; then
    echo "[dev] PHANTOM_BOOTSTRAP_ADMIN_PASSWORD is unset: on a fresh database the generated"
    echo "[dev] admin password is printed once in the backend log (WARNING)."
  fi
  exec "$ROOT/.venv/bin/python" -m uvicorn backend.main:app \
    --host "$BACKEND_HOST" --port "$BACKEND_PORT" --reload --reload-dir backend
}

# ----------------------------------------------------------------------------- frontend
setup_frontend() {
  if ! command -v npm > /dev/null 2>&1; then
    echo "[dev] npm not found: install Node.js 20+ to run the frontend" >&2
    exit 1
  fi
  if [[ ! -d frontend/node_modules || frontend/package-lock.json -nt frontend/node_modules ]]; then
    echo "[dev] installing frontend dependencies"
    (cd frontend && npm ci --no-audit --no-fund)
  fi
}

run_frontend() {
  echo "[dev] frontend: http://localhost:${FRONTEND_PORT}  (API: ${NEXT_PUBLIC_API_URL})"
  cd "$ROOT/frontend"
  exec ./node_modules/.bin/next dev --port "$FRONTEND_PORT"
}

# ----------------------------------------------------------------------------- main
case "$MODE" in
  backend)
    setup_backend
    run_backend
    ;;
  frontend)
    setup_frontend
    run_frontend
    ;;
  all)
    setup_backend
    setup_frontend
    # Each server runs in a background subshell that execs it, so these PIDs are the servers.
    run_backend &
    backend_pid=$!
    run_frontend &
    frontend_pid=$!
    cleanup() {
      trap - INT TERM EXIT
      kill "$backend_pid" "$frontend_pid" 2> /dev/null || true
      wait 2> /dev/null || true
    }
    trap cleanup EXIT
    trap 'exit 130' INT TERM
    # Stop both as soon as either exits (portable to bash 3.2, which lacks wait -n).
    while kill -0 "$backend_pid" 2> /dev/null && kill -0 "$frontend_pid" 2> /dev/null; do
      sleep 1
    done
    ;;
esac
