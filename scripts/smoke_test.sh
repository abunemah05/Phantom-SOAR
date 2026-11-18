#!/usr/bin/env bash
# End-to-end smoke test of a RUNNING Phantom SOAR stack through its single HTTPS origin.
#
#   scripts/smoke_test.sh [BASE_URL]            default https://localhost
#
# Environment:
#   PHANTOM_INGEST_TOKEN             token for the webhook step (a >= 32 character legacy token or a
#                                    per-sender token). Without it the ingest steps are skipped.
#   PHANTOM_BOOTSTRAP_ADMIN_USERNAME / PHANTOM_BOOTSTRAP_ADMIN_PASSWORD
#                                    sign-in used to read the alert back (username default "admin").
#                                    Without a password the sign-in step is skipped.
#   SMOKE_HTTP_URL                   e.g. http://localhost: checks the HTTP -> HTTPS redirect.
#   SMOKE_INSECURE=1                 accept the proxy's internal-CA certificate (default for localhost).
#   SMOKE_WAIT_SECONDS               how long to wait for /api/health (default 120).
# Secrets are read from the environment and never printed. Exit status 0 only if every executed check passed.
# shellcheck disable=SC2015  # ok()/bad() cannot fail, so "A && ok || bad" is a safe if-then-else here
set -uo pipefail

BASE="${1:-https://localhost}"
BASE="${BASE%/}"
WAIT="${SMOKE_WAIT_SECONDS:-120}"
CURL=(curl -sS --max-time 30)
if [[ "${SMOKE_INSECURE:-}" == "1" || "$BASE" == https://localhost* || "$BASE" == https://127.0.0.1* ]]; then
  CURL+=(-k)
fi

pass=0
fail=0
ok() { echo "ok   - $1"; pass=$((pass + 1)); }
bad() { echo "FAIL - $1" >&2; fail=$((fail + 1)); }
skip() { echo "skip - $1"; }

# status_of METHOD URL [curl args...] -> prints HTTP status
status_of() {
  local method="$1" url="$2"
  shift 2
  "${CURL[@]}" -o /dev/null -w '%{http_code}' -X "$method" "$@" "$url" 2> /dev/null || echo 000
}

json_get() { # json_get FIELD  (reads JSON on stdin; prints "" when missing)
  python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    v = d
    for part in sys.argv[1].split("."):
        v = v[part]
    print(v)
except Exception:
    print("")' "$1"
}

echo "Smoke test against $BASE"

# 1. health through the proxy
deadline=$((SECONDS + WAIT))
health=""
while ((SECONDS < deadline)); do
  health="$("${CURL[@]}" "$BASE/api/health" 2> /dev/null || true)"
  [[ "$(printf '%s' "$health" | json_get status)" == "healthy" ]] && break
  sleep 3
done
if [[ "$(printf '%s' "$health" | json_get status)" == "healthy" ]]; then
  ok "GET /api/health is healthy (database: $(printf '%s' "$health" | json_get database))"
else
  bad "GET /api/health did not become healthy within ${WAIT}s (last body: ${health:-none})"
  echo "Results: $pass passed, $fail failed"
  exit 1
fi

# 2. HTTP -> HTTPS redirect
if [[ -n "${SMOKE_HTTP_URL:-}" ]]; then
  code="$(status_of GET "${SMOKE_HTTP_URL%/}/")"
  location="$("${CURL[@]}" -o /dev/null -D - "${SMOKE_HTTP_URL%/}/" 2> /dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}')"
  if [[ "$code" =~ ^30[1278]$ && "$location" == https://* ]]; then ok "HTTP redirects to HTTPS ($code)"; else bad "HTTP did not redirect to HTTPS (status $code, location '$location')"; fi
fi

# 3. console and the paths that must not be exposed
code="$(status_of GET "$BASE/")"
[[ "$code" == "200" ]] && ok "GET / serves the console (200)" || bad "GET / returned $code"
for path in /docs /redoc /openapi.json; do
  code="$(status_of GET "$BASE$path")"
  [[ "$code" == "404" ]] && ok "GET $path is not exposed (404)" || bad "GET $path returned $code (expected 404)"
done
headers="$("${CURL[@]}" -o /dev/null -D - "$BASE/api/health" 2> /dev/null | tr -d '\r')"
if grep -qi '^x-content-type-options: nosniff' <<< "$headers"; then ok "security headers present"; else bad "X-Content-Type-Options missing"; fi
if grep -qi '^server:' <<< "$headers"; then bad "Server header is exposed"; else ok "Server header removed"; fi
code="$(status_of GET "$BASE/api/alerts")"
[[ "$code" == "401" || "$code" == "403" ]] && ok "GET /api/alerts without a session is refused ($code)" || bad "GET /api/alerts without a session returned $code"

# 4. webhook ingestion (simulation mode: nothing leaves the stack)
alert_id=""
payload='{"rule":{"id":"99001","level":7,"description":"Phantom smoke test alert"},"agent":{"id":"001","name":"smoke-test-host"},"data":{"srcip":"203.0.113.77"}}'
code="$(status_of POST "$BASE/api/webhooks/wazuh" -H 'Content-Type: application/json' -d "$payload")"
[[ "$code" == "401" || "$code" == "503" ]] && ok "webhook without a token is refused ($code)" || bad "webhook without a token returned $code"
if [[ -n "${PHANTOM_INGEST_TOKEN:-}" ]]; then
  body="$("${CURL[@]}" -X POST "$BASE/api/webhooks/wazuh" -H 'Content-Type: application/json' \
    -H "X-Phantom-Ingest-Token: $PHANTOM_INGEST_TOKEN" -d "$payload" 2> /dev/null || true)"
  alert_id="$(printf '%s' "$body" | json_get alert_id)"
  if [[ "$(printf '%s' "$body" | json_get status)" == "Success" && -n "$alert_id" ]]; then
    ok "webhook accepted the alert (alert #$alert_id, status $(printf '%s' "$body" | json_get current_status))"
  else
    bad "webhook did not accept the alert (response: ${body:0:300})"
  fi
else
  skip "webhook ingest (PHANTOM_INGEST_TOKEN not set)"
fi

# 5. sign in and read the alert back
if [[ -n "${PHANTOM_BOOTSTRAP_ADMIN_PASSWORD:-}" ]]; then
  user="${PHANTOM_BOOTSTRAP_ADMIN_USERNAME:-admin}"
  login_body="$(python3 -c 'import json,os; print(json.dumps({"username": os.environ.get("PHANTOM_BOOTSTRAP_ADMIN_USERNAME") or "admin", "password": os.environ["PHANTOM_BOOTSTRAP_ADMIN_PASSWORD"]}))')"
  resp="$("${CURL[@]}" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d "$login_body" 2> /dev/null || true)"
  token="$(printf '%s' "$resp" | json_get access_token)"
  if [[ -n "$token" ]]; then
    ok "sign-in as '$user' works"
    if [[ -n "$alert_id" ]]; then
      alerts="$("${CURL[@]}" "$BASE/api/alerts?limit=50" -H "Authorization: Bearer $token" 2> /dev/null || true)"
      if python3 -c 'import json,sys
ids = [a.get("alert_id") for a in json.loads(sys.stdin.read())]
sys.exit(0 if int(sys.argv[1]) in ids else 1)' "$alert_id" <<< "$alerts" 2> /dev/null; then
        ok "alert #$alert_id is listed by GET /api/alerts"
      else
        bad "alert #$alert_id was not found in GET /api/alerts"
      fi
    fi
  else
    bad "sign-in failed (${resp:0:200})"
  fi
else
  skip "sign-in (PHANTOM_BOOTSTRAP_ADMIN_PASSWORD not set)"
fi

echo "Results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
