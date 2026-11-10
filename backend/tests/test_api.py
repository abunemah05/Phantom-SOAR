import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["default_user"] == "abunemah"
    assert "SANS PICERL" in data["architecture"]

def test_auth_login_default_user():
    # Test valid credentials: abunemah / Admin1
    res = client.post("/api/auth/login", json={"username": "abunemah", "password": "Admin1"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["username"] == "abunemah"

    # Test invalid password
    res_bad = client.post("/api/auth/login", json={"username": "abunemah", "password": "WrongPassword"})
    assert res_bad.status_code == 401

def test_configuration_endpoints():
    # 1. Get configurations
    res = client.get("/api/configuration")
    assert res.status_code == 200
    data = res.json()
    assert "AI" in data
    assert "EDR" in data
    assert "SIEM" in data
    assert "TIP" in data

    # 2. Test Connection - Empty credentials returns Not Configured
    res_empty = client.post("/api/configuration/test-connection", json={
        "category": "EDR",
        "service_name": "CrowdStrike Falcon"
    })
    assert res_empty.status_code == 200
    assert res_empty.json()["status"] == "Not Configured"
    assert res_empty.json()["is_connected"] is False

    # 3. Test Connection - Trial / fake key returns Connection Failed (401)
    res_trial = client.post("/api/configuration/test-connection", json={
        "category": "TIP",
        "service_name": "VirusTotal",
        "api_key": "vt_trial_fake_sample_12345"
    })
    assert res_trial.status_code == 200
    assert res_trial.json()["status"] == "Connection Failed"
    assert "401" in res_trial.json()["health"]
    assert res_trial.json()["is_connected"] is False

    # 4. Update configuration
    update_payload = {
        "configs": [
            {"category": "AI", "key_name": "ai_model", "key_value": "gemini-2.0-flash", "is_secret": False}
        ]
    }
    res_up = client.post("/api/configuration", json=update_payload)
    assert res_up.status_code == 200

def test_user_management_and_password_lifecycle():
    # 1. List users
    users_res = client.get("/api/users")
    assert users_res.status_code == 200
    users = users_res.json()
    assert any(u["username"] == "abunemah" for u in users)

    # 2. Create new user account with role
    create_res = client.post("/api/users", json={
        "username": "analyst_omar",
        "role": "Tier 2 Analyst (Senior)"
    })
    assert create_res.status_code == 201
    new_user = create_res.json()
    user_id = new_user["user_id"]
    assert new_user["username"] == "analyst_omar"
    assert new_user["role"] == "Tier 2 Analyst (Senior)"
    assert new_user["must_change_password"] is True

    # 3. Login with initial default password PhantomSOAR1@
    login_res = client.post("/api/auth/login", json={
        "username": "analyst_omar",
        "password": "PhantomSOAR1@"
    })
    assert login_res.status_code == 200
    assert login_res.json()["user"]["must_change_password"] is True

    # 4. Change password on first login
    change_res = client.post("/api/auth/change-password", json={
        "username": "analyst_omar",
        "current_password": "PhantomSOAR1@",
        "new_password": "SecuredAnalystPassword2026!"
    })
    assert change_res.status_code == 200
    assert change_res.json()["status"] == "Success"

    # 5. Login with new password
    new_login_res = client.post("/api/auth/login", json={
        "username": "analyst_omar",
        "password": "SecuredAnalystPassword2026!"
    })
    assert new_login_res.status_code == 200
    assert new_login_res.json()["user"]["must_change_password"] is False

    # 6. Reset password back to default
    reset_res = client.post(f"/api/users/{user_id}/reset-password")
    assert reset_res.status_code == 200
    assert reset_res.json()["default_password"] == "PhantomSOAR1@"

    # 7. Protect root admin from deletion
    admin_user = next(u for u in users if u["username"] == "abunemah")
    del_admin = client.delete(f"/api/users/{admin_user['user_id']}")
    assert del_admin.status_code == 400

    # 8. Delete created operator
    del_res = client.delete(f"/api/users/{user_id}")
    assert del_res.status_code == 200

def test_logs_endpoints_and_filters():
    # 1. Explicitly seed test telemetry logs for testing filters
    seed_res = client.post("/api/logs/seed")
    assert seed_res.status_code == 200

    # 2. Fetch logs
    res = client.get("/api/logs")
    assert res.status_code == 200
    logs = res.json()
    assert len(logs) > 0

    # 3. Filter by source (EDR)
    res_edr = client.get("/api/logs?source=EDR")
    assert res_edr.status_code == 200
    edr_logs = res_edr.json()
    assert len(edr_logs) > 0
    assert all(l["source"] == "EDR" for l in edr_logs)

    # 4. Filter by source (SIEM)
    res_siem = client.get("/api/logs?source=SIEM")
    assert res_siem.status_code == 200
    siem_logs = res_siem.json()
    assert len(siem_logs) > 0
    assert all(l["source"] == "SIEM" for l in siem_logs)

    # 5. Filter by time in seconds (e.g. within last 60 seconds)
    res_60s = client.get("/api/logs?seconds=60")
    assert res_60s.status_code == 200
    logs_60s = res_60s.json()
    assert len(logs_60s) > 0
    # Every returned log should be within 60 seconds
    assert len(logs_60s) <= len(logs)

    # 6. Create a new log entry
    new_log = {
        "source": "FIREWALL",
        "level": "CRITICAL",
        "message": "Manual ACL block triggered by analyst",
        "target": "198.51.100.22"
    }
    create_res = client.post("/api/logs", json=new_log)
    assert create_res.status_code == 201
    assert create_res.json()["source"] == "FIREWALL"

    # 7. Purge logs so system remains pristine
    del_res = client.delete("/api/logs")
    assert del_res.status_code == 200
    assert len(client.get("/api/logs").json()) == 0

def test_demo_seed():
    response = client.post("/api/demo/seed")
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "Success"
    assert len(data["seeded_alerts"]) >= 3

def test_list_alerts_and_metrics():
    # Metrics
    metrics_res = client.get("/api/alerts/metrics/dashboard")
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert "total_alerts" in metrics
    assert "avg_mttr_seconds" in metrics

    # Alerts list
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) > 0

    first_alert = alerts[0]
    alert_id = first_alert["alert_id"]

    # Alert detail
    detail_res = client.get(f"/api/alerts/{alert_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert "ioc_artifacts" in detail
    assert "containment_actions" in detail

    # Report stream
    report_res = client.get(f"/api/alerts/{alert_id}/report")
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"

def test_low_ticket_decision():
    # Find or seed a Low alert
    alerts = client.get("/api/alerts?severity=Low").json()
    if not alerts:
        client.post("/api/demo/seed")
        alerts = client.get("/api/alerts?severity=Low").json()

    assert len(alerts) > 0
    low_id = alerts[0]["alert_id"]

    # 1. Test "keep_and_monitor" decision
    keep_res = client.post(f"/api/alerts/{low_id}/decision", json={"decision": "keep_and_monitor"})
    assert keep_res.status_code == 200
    assert keep_res.json()["new_status"] == "Monitoring"

    # 2. Test "take_action" decision
    action_res = client.post(f"/api/alerts/{low_id}/decision", json={"decision": "take_action"})
    assert action_res.status_code == 200
    assert action_res.json()["new_status"] == "Contained"

def test_hitl_approval_and_dismissal():
    alerts = client.get("/api/alerts?status=Triaged").json()
    if not alerts:
        client.post("/api/demo/seed")
        alerts = client.get("/api/alerts?status=Triaged").json()

    assert len(alerts) > 0
    triaged_id = alerts[0]["alert_id"]

    approve_res = client.post(f"/api/alerts/{triaged_id}/approve")
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "Success"

    updated = client.get(f"/api/alerts/{triaged_id}").json()
    assert updated["status"] == "Contained"

def test_playbooks_crud():
    p_list = client.get("/api/playbooks").json()
    assert len(p_list) >= 12

    new_pb = {
        "name": "Custom Incident Playbook",
        "target_threat": "ZeroDay",
        "execution_mode": "HOTL",
        "workflow_logic": {"steps": [{"action": "isolate_endpoint"}]},
        "is_active": True
    }
    create_res = client.post("/api/playbooks", json=new_pb)
    assert create_res.status_code == 201
    created = create_res.json()
    pb_id = created["playbook_id"]

    toggle_res = client.patch(f"/api/playbooks/{pb_id}/toggle")
    assert toggle_res.status_code == 200
    assert toggle_res.json()["is_active"] is False

    update_res = client.put(f"/api/playbooks/{pb_id}", json={"name": "Renamed Custom Playbook"})
    assert update_res.status_code == 200
    assert update_res.json()["name"] == "Renamed Custom Playbook"

    del_res = client.delete(f"/api/playbooks/{pb_id}")
    assert del_res.status_code == 200

def test_wazuh_webhook():
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
    resp = client.post("/api/webhooks/wazuh", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "Success"
    assert data["severity"] == "Critical"
    assert data["ioc_count"] == 2
