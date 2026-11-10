from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest

from backend.security import create_access_token, JWT_SECRET_KEY, JWT_ALGORITHM
from backend.tests.conftest import ADMIN_USERNAME, ADMIN_PASSWORD


def bearer(username: str, **claims) -> dict:
    return {"Authorization": f"Bearer {create_access_token({'sub': username, **claims})}"}


def provision(client, admin_headers, username: str, role: str = "SOC Analyst") -> dict:
    """Create (or recreate) an operator account; returns the create response incl. temporary_password."""
    for u in client.get("/api/users", headers=admin_headers).json():
        if u["username"] == username:
            client.delete(f"/api/users/{u['user_id']}", headers=admin_headers)
    res = client.post("/api/users", json={"username": username, "role": role}, headers=admin_headers)
    assert res.status_code == 201, res.text
    return res.json()


# --- Health & login ---------------------------------------------------------------
def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert "SANS PICERL" in data["architecture"]
    assert "default_user" not in data
    assert ADMIN_USERNAME not in response.text


def test_auth_login_bootstrap_admin(client):
    res = client.post("/api/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert res.status_code == 200
    data = res.json()
    assert data["access_token"]
    assert data["mfa_required"] is False
    assert data["user"]["username"] == ADMIN_USERNAME
    assert data["user"]["must_change_password"] is False
    assert "password_hash" not in data["user"] and "mfa_secret" not in data["user"]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert me.status_code == 200
    assert me.json()["username"] == ADMIN_USERNAME

    assert client.post("/api/auth/login", json={"username": ADMIN_USERNAME, "password": "Admin1"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "no_such_operator", "password": "whatever-123456"}).status_code == 401
    # A successful sign-in resets the failure counter, so the bootstrap admin is never left near lockout.
    assert client.post("/api/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}).status_code == 200


# --- Token handling ------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/api/alerts", "/api/alerts/metrics/dashboard", "/api/playbooks", "/api/users",
                                  "/api/configuration", "/api/configuration/runtime-status",
                                  "/api/configuration/hotl-status", "/api/logs", "/api/reports/analysts",
                                  "/api/auth/me"])
def test_protected_routes_require_token(client, path):
    res = client.get(path)
    assert res.status_code == 401
    assert res.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("method,path", [("delete", "/api/alerts/purge"), ("post", "/api/demo/seed"),
                                         ("post", "/api/configuration/hotl-toggle"), ("delete", "/api/logs"),
                                         ("post", "/api/configuration/test-connection")])
def test_mutating_routes_require_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_invalid_tokens_are_rejected(client):
    now = datetime.now(timezone.utc)
    expired = create_access_token({"sub": ADMIN_USERNAME}, expires_delta=timedelta(seconds=-5))
    forged = jwt.encode({"sub": ADMIN_USERNAME, "iat": now, "exp": now + timedelta(hours=1)},
                        "not-the-server-secret", algorithm="HS256")
    for token in ("garbage", "soar_token_admin", expired, forged, create_access_token({"sub": "ghost_user"})):
        res = client.get("/api/alerts", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401, token
    assert client.get("/api/alerts", headers={"Authorization": "Basic abc"}).status_code == 401


def test_tokens_issued_before_password_change_are_rejected(client, admin_headers):
    provision(client, admin_headers, "stale_session_user")
    now = datetime.now(timezone.utc)
    stale = jwt.encode({"sub": "stale_session_user", "iat": now - timedelta(hours=1), "exp": now + timedelta(hours=1)},
                       JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    assert client.get("/api/alerts", headers={"Authorization": f"Bearer {stale}"}).status_code == 401


def test_logout_revokes_token(client):
    token = client.post("/api/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.post("/api/auth/logout", headers=headers).json()["status"] == "Success"
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_service_accounts_cannot_use_operator_api(client, admin_headers):
    from backend.database import SessionLocal
    from backend.models import User

    created = provision(client, admin_headers, "svc_agent_probe")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "svc_agent_probe").first()
        user.is_service_account = True
        db.commit()
    finally:
        db.close()

    assert client.get("/api/alerts", headers=bearer("svc_agent_probe")).status_code == 403
    login = client.post("/api/auth/login", json={"username": "svc_agent_probe", "password": created["temporary_password"]})
    assert login.status_code == 403


def test_inactive_user_is_rejected(client, admin_headers):
    created = provision(client, admin_headers, "inactive_probe")
    res = client.put(f"/api/users/{created['user_id']}", json={"is_active": False}, headers=admin_headers)
    assert res.status_code == 200
    assert client.get("/api/alerts", headers=bearer("inactive_probe")).status_code == 403


def test_brute_force_lockout_and_unlock(client, admin_headers):
    created = provision(client, admin_headers, "lockout_probe")
    for _ in range(4):
        assert client.post("/api/auth/login", json={"username": "lockout_probe", "password": "wrong-password-xyz"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "lockout_probe", "password": "wrong-password-xyz"}).status_code == 403
    good = {"username": "lockout_probe", "password": created["temporary_password"]}
    assert client.post("/api/auth/login", json=good).status_code == 403  # locked even with the right password

    assert client.post(f"/api/users/{created['user_id']}/unlock", headers=admin_headers).status_code == 200
    assert client.post("/api/auth/login", json=good).status_code == 200


# --- Webhook ingestion token ---------------------------------------------------------
def test_webhooks_require_ingest_token(client, monkeypatch):
    payload = {"rule": {"id": "5710", "level": 5, "description": "sshd: attempt to login using a non-existent user"}}
    for path in ("/api/webhooks/wazuh", "/api/webhooks/edr", "/api/webhooks/xdr"):
        assert client.post(path, json=payload).status_code == 401
        assert client.post(path, json=payload, headers={"X-Phantom-Ingest-Token": "wrong"}).status_code == 401
        # An operator session is not an ingestion credential.
        assert client.post(path, json=payload, headers=bearer(ADMIN_USERNAME)).status_code == 401

    monkeypatch.delenv("PHANTOM_INGEST_TOKEN", raising=False)
    assert client.post("/api/webhooks/wazuh", json=payload, headers={"X-Phantom-Ingest-Token": "anything"}).status_code == 503


def test_wazuh_webhook(client, ingest_headers):
    payload = {
        "rule": {
            "id": "99901",
            "level": 13,
            "description": "Critical Cobalt Strike Beacon Detection",
            "mitre": {"id": ["T1071"], "tactic": ["Command and Control"]}
        },
        "agent": {"id": "010", "name": "workstation-10"},
        "data": {
            "srcip": "185.220.101.5",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    }
    resp = client.post("/api/webhooks/wazuh", json=payload, headers=ingest_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "Success"
    assert data["severity"] == "Critical"
    assert data["ioc_count"] == 2


# --- Configuration -------------------------------------------------------------------
def test_configuration_categories_and_defaults(client, admin_headers):
    from backend.integration_config import INTEGRATION_KEYS

    data = client.get("/api/configuration", headers=admin_headers).json()
    assert set(data) == {"TIP", "SIEM", "IAM", "ITSM", "ORCHESTRATION", "AGENT"}
    listed = {key for keys in data.values() for key in keys}
    assert listed == set(INTEGRATION_KEYS)

    assert data["ORCHESTRATION"]["simulation_mode"]["value"] == "true"
    assert data["AGENT"]["agent_autonomy"]["value"] == "recommend_only"
    assert data["AGENT"]["agent_min_confidence"]["value"] == "0.85"
    assert data["SIEM"]["siem_manager_url"]["value"] == ""
    assert data["SIEM"]["siem_manager_url"]["is_set"] is False
    for key in ("virustotal_api_key", "siem_password", "okta_api_token", "slack_webhook_url", "jira_webhook_url"):
        assert data[INTEGRATION_KEYS[key][0]][key]["is_secret"] is True
    assert set(data["TIP"]["virustotal_api_key"]) >= {"value", "is_secret", "is_set", "preview", "updated_at"}


def test_configuration_secrets_are_masked_and_kept(client, admin_headers):
    secret = "otx-test-secret-value-9f3c"
    try:
        res = client.post("/api/configuration", headers=admin_headers, json={"configs": [
            {"category": "TIP", "key_name": "otx_api_key", "key_value": secret, "is_secret": False},
        ]})
        assert res.status_code == 200, res.text
        assert "otx_api_key" in res.json()["updated"]

        raw = client.get("/api/configuration", headers=admin_headers)
        assert secret not in raw.text
        item = raw.json()["TIP"]["otx_api_key"]
        assert (item["value"], item["is_secret"], item["is_set"], item["preview"]) == ("", True, True, "••••9f3c")

        # Saving the form with an empty secret keeps the stored value.
        res = client.post("/api/configuration", headers=admin_headers, json={"configs": [
            {"category": "TIP", "key_name": "otx_api_key", "key_value": "", "is_secret": True},
        ]})
        assert res.status_code == 200
        assert "otx_api_key" in res.json()["unchanged"]
        assert client.get("/api/configuration", headers=admin_headers).json()["TIP"]["otx_api_key"]["preview"] == "••••9f3c"
        assert client.get("/api/configuration/runtime-status", headers=admin_headers).json()["integrations"]["otx"] is True
    finally:
        res = client.post("/api/configuration", headers=admin_headers, json={"configs": [
            {"category": "TIP", "key_name": "otx_api_key", "key_value": "", "is_secret": True, "clear": True},
        ]})
    assert res.status_code == 200
    item = client.get("/api/configuration", headers=admin_headers).json()["TIP"]["otx_api_key"]
    assert item["is_set"] is False and item["preview"] is None


def test_configuration_rejects_invalid_values(client, admin_headers):
    bad = [
        {"category": "AI", "key_name": "ai_api_key", "key_value": "x"},
        {"category": "AGENT", "key_name": "agent_autonomy", "key_value": "full_auto"},
        {"category": "AGENT", "key_name": "agent_min_confidence", "key_value": "1.5"},
        {"category": "SIEM", "key_name": "siem_manager_url", "key_value": "ftp://wazuh.local"},
        {"category": "ORCHESTRATION", "key_name": "protected_ips", "key_value": "10.0.0.1, not-an-ip"},
        {"category": "TIP", "key_name": "hotl_enabled", "key_value": "true"},
    ]
    for item in bad:
        res = client.post("/api/configuration", headers=admin_headers, json={"configs": [item]})
        assert res.status_code == 400, item


def test_runtime_status_shape(client, admin_headers):
    res = client.get("/api/configuration/runtime-status", headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["simulation_mode"] is True
    assert isinstance(data["hotl_enabled"], bool)
    assert set(data["integrations"]) == {"virustotal", "abuseipdb", "otx", "threatfox", "nvd", "wazuh", "okta", "jira", "slack"}
    assert all(isinstance(v, bool) for v in data["integrations"].values())
    assert not any(data["integrations"].values())  # tests run with no third-party credentials


def test_hotl_status_and_toggle(client, admin_headers):
    initial = client.get("/api/configuration/hotl-status", headers=admin_headers).json()["hotl_enabled"]
    try:
        res = client.post("/api/configuration/hotl-toggle", json={"enabled": not initial}, headers=admin_headers)
        assert res.status_code == 200
        assert res.json()["hotl_enabled"] is (not initial)
        assert client.get("/api/configuration/hotl-status", headers=admin_headers).json()["hotl_enabled"] is (not initial)
    finally:
        client.post("/api/configuration/hotl-toggle", json={"enabled": initial}, headers=admin_headers)


def test_test_connection_is_honest(client, admin_headers, monkeypatch):
    res = client.post("/api/configuration/test-connection", headers=admin_headers,
                      json={"category": "TIP", "service_name": "VirusTotal"})
    assert res.status_code == 200
    assert res.json()["status"] == "Not Configured"
    assert res.json()["is_connected"] is False

    res = client.post("/api/configuration/test-connection", headers=admin_headers,
                      json={"service_name": "Slack", "endpoint_url": "https://hooks.slack.com/services/T/B/X"})
    assert res.json()["status"] == "Configured (not tested to avoid posting)"
    assert res.json()["is_connected"] is False

    assert client.post("/api/configuration/test-connection", headers=admin_headers,
                       json={"service_name": "CrowdStrike Falcon"}).status_code == 400

    import backend.routers.config as config_router

    real_client = httpx.Client
    seen = []

    def fake_client(handler):
        def factory(**kwargs):
            kwargs.pop("verify", None)
            return real_client(transport=httpx.MockTransport(handler), **kwargs)
        return factory

    def vt_handler(request):
        seen.append(request)
        return httpx.Response(200 if request.headers.get("x-apikey") == "good-key" else 401, json={})

    monkeypatch.setattr(config_router.httpx, "Client", fake_client(vt_handler))
    ok = client.post("/api/configuration/test-connection", headers=admin_headers,
                     json={"service_name": "virustotal", "api_key": "good-key"}).json()
    assert ok["status"] == "Connected" and ok["is_connected"] is True
    bad = client.post("/api/configuration/test-connection", headers=admin_headers,
                      json={"service_name": "virustotal", "api_key": "bad-key"}).json()
    assert bad["status"] == "Auth failed" and bad["is_connected"] is False
    assert seen[0].url.path == "/api/v3/ip_addresses/8.8.8.8"

    def down_handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(config_router.httpx, "Client", fake_client(down_handler))
    down = client.post("/api/configuration/test-connection", headers=admin_headers,
                       json={"service_name": "wazuh", "endpoint_url": "https://wazuh.invalid:55000",
                             "username": "wazuh", "api_key": "pw"}).json()
    assert down["status"] == "Unreachable" and down["is_connected"] is False


def test_analyst_cannot_read_or_change_configuration(client, admin_headers):
    provision(client, admin_headers, "config_analyst_probe", role="SOC Analyst")
    headers = bearer("config_analyst_probe")
    assert client.get("/api/configuration", headers=headers).status_code == 403
    assert client.post("/api/configuration", headers=headers, json={"configs": []}).status_code == 403
    assert client.post("/api/configuration/test-connection", headers=headers, json={"service_name": "virustotal"}).status_code == 403
    assert client.post("/api/configuration/hotl-toggle", headers=headers, json={"enabled": False}).status_code == 403
    assert client.get("/api/configuration/runtime-status", headers=headers).status_code == 200
    assert client.get("/api/configuration/hotl-status", headers=headers).status_code == 200


def test_security_engineer_can_read_but_not_write_configuration(client, admin_headers):
    provision(client, admin_headers, "config_engineer_probe", role="Security Engineer")
    headers = bearer("config_engineer_probe")
    assert client.get("/api/configuration", headers=headers).status_code == 200
    assert client.post("/api/configuration", headers=headers, json={"configs": []}).status_code == 403


# --- Users -----------------------------------------------------------------------------
def test_user_management_and_password_lifecycle(client, admin_headers):
    created = provision(client, admin_headers, "analyst_omar", role="Tier 2 Analyst (Senior Responder)")
    user_id = created["user_id"]
    temp = created["temporary_password"]
    assert created["must_change_password"] is True
    assert created["role"] == "Tier 2 Analyst (Senior Responder)"
    assert len(temp) >= 15 and temp != "PhantomSOAR1@"

    users = client.get("/api/users", headers=admin_headers).json()
    assert any(u["username"] == ADMIN_USERNAME for u in users)
    assert all("password_hash" not in u and "mfa_secret" not in u for u in users)

    # First sign-in: the session can only see its own profile until the password is changed.
    login = client.post("/api/auth/login", json={"username": "analyst_omar", "password": temp})
    assert login.status_code == 200
    assert login.json()["user"]["must_change_password"] is True
    pending = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.get("/api/auth/me", headers=pending).status_code == 200
    assert client.get("/api/alerts", headers=pending).status_code == 403

    change = client.post("/api/auth/change-password", json={
        "username": "analyst_omar", "current_password": temp, "new_password": "SecuredAnalystPassword2026!"
    })
    assert change.status_code == 200
    assert change.json()["status"] == "Success"
    fresh = {"Authorization": f"Bearer {change.json()['access_token']}"}
    assert client.get("/api/alerts", headers=fresh).status_code == 200
    assert client.get("/api/alerts", headers=pending).status_code in (401, 403)

    relogin = client.post("/api/auth/login", json={"username": "analyst_omar", "password": "SecuredAnalystPassword2026!"})
    assert relogin.status_code == 200
    assert relogin.json()["user"]["must_change_password"] is False

    # Analysts are not administrators.
    assert client.get("/api/users", headers=fresh).status_code == 403

    reset = client.post(f"/api/users/{user_id}/reset-password", headers=admin_headers)
    assert reset.status_code == 200
    assert reset.json()["temporary_password"] not in ("", "PhantomSOAR1@")
    assert client.post("/api/auth/login", json={"username": "analyst_omar", "password": "SecuredAnalystPassword2026!"}).status_code == 401

    assert client.post("/api/users", json={"username": "role_probe", "role": "Supreme Overlord"}, headers=admin_headers).status_code == 400

    admin_user = next(u for u in users if u["username"] == ADMIN_USERNAME)
    assert client.delete(f"/api/users/{admin_user['user_id']}", headers=admin_headers).status_code == 400
    assert client.put(f"/api/users/{admin_user['user_id']}", json={"is_active": False}, headers=admin_headers).status_code == 400

    assert client.delete(f"/api/users/{user_id}", headers=admin_headers).status_code == 200


def test_roles_catalog(client, admin_headers):
    roles = client.get("/api/users/roles", headers=admin_headers).json()
    assert {r["role"] for r in roles} >= {"Admin", "Security Engineer", "SOC Analyst"}


# --- Logs ------------------------------------------------------------------------------
def test_logs_endpoints_and_filters(client, admin_headers):
    assert client.post("/api/logs/seed", headers=admin_headers).status_code in (404, 405)

    for source in ("FIREWALL", "EDR"):
        res = client.post("/api/logs", headers=admin_headers, json={
            "source": source, "level": "ACTION", "message": f"Manual {source} note", "target": "198.51.100.22"
        })
        assert res.status_code == 201
        assert res.json()["source"] == source
        assert res.json()["details"]["recorded_by"] == ADMIN_USERNAME

    assert len(client.get("/api/logs", headers=admin_headers).json()) >= 2
    edr = client.get("/api/logs?source=EDR", headers=admin_headers).json()
    assert edr and all(entry["source"] == "EDR" for entry in edr)
    assert len(client.get("/api/logs?seconds=60", headers=admin_headers).json()) >= 2
    assert client.post("/api/logs", headers=admin_headers, json={"source": "EDR", "level": "LOUD", "message": "x"}).status_code == 422

    provision(client, admin_headers, "logs_analyst_probe")
    analyst = bearer("logs_analyst_probe")
    assert client.get("/api/logs", headers=analyst).status_code == 200
    assert client.post("/api/logs", headers=analyst, json={"source": "EDR", "message": "x"}).status_code == 403
    assert client.delete("/api/logs", headers=analyst).status_code == 403

    res = client.delete("/api/logs", headers=admin_headers)
    assert res.status_code == 200
    remaining = client.get("/api/logs", headers=admin_headers).json()
    assert len(remaining) == 1 and remaining[0]["source"] == "AUDIT"  # the purge itself is recorded


# --- Smoke tests over the authenticated alert / playbook API ------------------------
def test_list_alerts_and_metrics(client, admin_headers):
    metrics = client.get("/api/alerts/metrics/dashboard", headers=admin_headers)
    assert metrics.status_code == 200
    assert "total_alerts" in metrics.json()
    assert client.get("/api/alerts", headers=admin_headers).status_code == 200


def test_playbooks_crud(client, admin_headers):
    assert len(client.get("/api/playbooks", headers=admin_headers).json()) >= 12

    new_pb = {
        "name": "Custom Incident Playbook",
        "target_threat": "ZeroDay",
        "execution_mode": "HITL",
        "workflow_logic": {"steps": [{"action": "create_ticket"}]},
        "is_active": True
    }
    create_res = client.post("/api/playbooks", json=new_pb, headers=admin_headers)
    assert create_res.status_code == 201
    pb_id = create_res.json()["playbook_id"]

    toggle_res = client.patch(f"/api/playbooks/{pb_id}/toggle", headers=admin_headers)
    assert toggle_res.status_code == 200
    assert toggle_res.json()["is_active"] is False

    update_res = client.put(f"/api/playbooks/{pb_id}", json={"name": "Renamed Custom Playbook"}, headers=admin_headers)
    assert update_res.status_code == 200
    assert update_res.json()["name"] == "Renamed Custom Playbook"

    assert client.delete(f"/api/playbooks/{pb_id}", headers=admin_headers).status_code == 200


def test_demo_seed(client, admin_headers):
    response = client.post("/api/demo/seed", headers=admin_headers)
    assert response.status_code == 201, response.text
    data = response.json()
    assert data["status"] == "Success"
    assert len(data["seeded_alerts"]) >= 3


def test_alert_detail_and_report(client, admin_headers):
    alerts = client.get("/api/alerts", headers=admin_headers).json()
    if not alerts:
        client.post("/api/demo/seed", headers=admin_headers)
        alerts = client.get("/api/alerts", headers=admin_headers).json()
    assert alerts
    alert_id = alerts[0]["alert_id"]

    detail = client.get(f"/api/alerts/{alert_id}", headers=admin_headers)
    assert detail.status_code == 200
    assert "ioc_artifacts" in detail.json()
    assert "containment_actions" in detail.json()

    report = client.get(f"/api/alerts/{alert_id}/report", headers=admin_headers)
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"


def test_low_ticket_decision(client, admin_headers):
    alerts = client.get("/api/alerts?severity=Low", headers=admin_headers).json()
    if not alerts:
        client.post("/api/demo/seed", headers=admin_headers)
        alerts = client.get("/api/alerts?severity=Low", headers=admin_headers).json()
    assert alerts
    low_id = alerts[0]["alert_id"]

    keep_res = client.post(f"/api/alerts/{low_id}/decision", json={"decision": "keep_and_monitor"}, headers=admin_headers)
    assert keep_res.status_code == 200
    assert keep_res.json()["new_status"] == "Monitoring"


def test_hitl_approval(client, admin_headers):
    alerts = client.get("/api/alerts?status=Triaged", headers=admin_headers).json()
    if not alerts:
        client.post("/api/demo/seed", headers=admin_headers)
        alerts = client.get("/api/alerts?status=Triaged", headers=admin_headers).json()
    if not alerts:
        pytest.skip("No alert is waiting for analyst approval.")
    triaged_id = alerts[0]["alert_id"]

    approve_res = client.post(f"/api/alerts/{triaged_id}/approve", headers=admin_headers)
    assert approve_res.status_code == 200, approve_res.text


def test_service_account_api_keys(client, admin_headers):
    for u in client.get("/api/users", headers=admin_headers).json():
        if u["username"] == "triage-agent-probe":
            client.delete(f"/api/users/{u['user_id']}", headers=admin_headers)
    created = client.post("/api/users/service-accounts", json={"username": "triage-agent-probe"}, headers=admin_headers)
    assert created.status_code == 201, created.text
    account = created.json()
    key = account["api_key"]
    assert account["is_service_account"] is True
    assert key.startswith(account["api_key_prefix"] + "_")

    listed = next(u for u in client.get("/api/users", headers=admin_headers).json() if u["username"] == "triage-agent-probe")
    assert listed["api_key_prefix"] == account["api_key_prefix"] and "api_key" not in listed

    who = client.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": key})
    assert who.status_code == 200 and who.json()["username"] == "triage-agent-probe"
    assert client.get("/api/auth/service-account", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    assert client.get("/api/auth/service-account").status_code == 401
    assert client.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": key + "x"}).status_code == 401
    # Operator sessions are not agent credentials, and agent keys are not operator sessions.
    assert client.get("/api/auth/service-account", headers=admin_headers).status_code == 401
    assert client.get("/api/alerts", headers={"Authorization": f"Bearer {key}"}).status_code == 401
    assert client.get("/api/alerts", headers={"X-Phantom-Agent-Key": key}).status_code == 401

    rotated = client.post(f"/api/users/{account['user_id']}/rotate-api-key", headers=admin_headers)
    assert rotated.status_code == 200
    assert client.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": key}).status_code == 401
    new_key = rotated.json()["api_key"]
    assert client.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": new_key}).status_code == 200

    assert client.put(f"/api/users/{account['user_id']}", json={"role": "Admin"}, headers=admin_headers).status_code == 400
    assert client.post(f"/api/users/{account['user_id']}/reset-password", headers=admin_headers).status_code == 400
    assert client.put(f"/api/users/{account['user_id']}", json={"is_active": False}, headers=admin_headers).status_code == 200
    assert client.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": new_key}).status_code == 403
    assert client.delete(f"/api/users/{account['user_id']}", headers=admin_headers).status_code == 200
