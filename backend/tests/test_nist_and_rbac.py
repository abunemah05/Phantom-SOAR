import pytest
import pyotp
from fastapi.testclient import TestClient
from backend.main import app
from backend.security import hash_password, verify_password, check_nist_password_policy, is_compromised_password

client = TestClient(app)

def test_argon2_hashing_and_verification():
    raw_password = "SuperSecureSecretPassphrase2026!"
    hashed = hash_password(raw_password)
    assert hashed.startswith("$argon2")
    assert verify_password(raw_password, hashed) is True
    assert verify_password("IncorrectPassphrase", hashed) is False

def test_nist_password_policy_validation():
    # 1. Single-factor account requires >= 15 characters
    valid, msg = check_nist_password_policy("short_pass_123", mfa_enabled=False)
    assert valid is False
    assert "at least 15 characters" in msg

    # 2. MFA-enabled account allows >= 8 characters
    valid_mfa, _ = check_nist_password_policy("mfa_pass_8", mfa_enabled=True)
    assert valid_mfa is True

    # 3. Arbitrary complexity (no symbols/digits required) is allowed if length met
    valid_passphrase, _ = check_nist_password_policy("correct horse battery staple enterprise", mfa_enabled=False)
    assert valid_passphrase is True

    # 4. Compromised passwords blocked
    assert is_compromised_password("password123") is True
    valid_comp, msg_comp = check_nist_password_policy("password1234567", mfa_enabled=False)
    assert valid_comp is False

def test_mfa_workflow_and_login_challenge():
    # 1. Login as root admin
    admin_login = client.post("/api/auth/login", json={"username": "abunemah", "password": "Admin1"})
    assert admin_login.status_code == 200
    token = admin_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Setup MFA
    setup_res = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup_res.status_code == 200
    mfa_data = setup_res.json()
    secret = mfa_data["secret"]
    assert "otpauth://" in mfa_data["provisioning_uri"]

    # 3. Invalid code rejection
    invalid_verify = client.post("/api/auth/mfa/verify", json={"code": "000000"}, headers=headers)
    assert invalid_verify.status_code == 400

    # 4. Valid TOTP code verification
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    verify_res = client.post("/api/auth/mfa/verify", json={"code": valid_code}, headers=headers)
    assert verify_res.status_code == 200
    assert verify_res.json()["mfa_enabled"] is True

    # 5. Login now challenges for MFA code
    login_challenge = client.post("/api/auth/login", json={"username": "abunemah", "password": "Admin1"})
    assert login_challenge.status_code == 200
    assert login_challenge.json()["mfa_required"] is True
    assert login_challenge.json()["access_token"] == ""

    # 6. Complete MFA login with fresh code
    mfa_code = totp.now()
    login_success = client.post("/api/auth/login", json={
        "username": "abunemah",
        "password": "Admin1",
        "mfa_code": mfa_code
    })
    assert login_success.status_code == 200
    assert login_success.json()["mfa_required"] is False
    assert len(login_success.json()["access_token"]) > 10

    # 7. Disable MFA to reset root admin state for subsequent tests
    disable_res = client.post("/api/auth/mfa/disable", headers=headers)
    assert disable_res.status_code == 200
    assert disable_res.json()["mfa_enabled"] is False

def test_rbac_admin_vs_soc_analyst():
    # 1. Create a pure SOC Analyst account
    admin_login = client.post("/api/auth/login", json={"username": "abunemah", "password": "Admin1"})
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Clean up or create analyst
    analyst_username = "analyst_rbac_test"
    client.post("/api/users", json={"username": analyst_username, "role": "SOC Analyst Tier 1"}, headers=admin_headers)

    # 2. Login as SOC Analyst
    analyst_login = client.post("/api/auth/login", json={"username": analyst_username, "password": "PhantomSOAR1@"})
    assert analyst_login.status_code == 200
    analyst_token = analyst_login.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 3. SOC Analyst attempts to access Admin User Management -> MUST FAIL with 403
    forbidden_users = client.get("/api/users", headers=analyst_headers)
    assert forbidden_users.status_code == 403
    assert "Operation requires SOC Administrator privileges" in forbidden_users.json()["detail"]

    forbidden_create = client.post("/api/users", json={"username": "intruder_user", "role": "Admin"}, headers=analyst_headers)
    assert forbidden_create.status_code == 403

    # 4. SOC Analyst attempts to access Admin Reporting Dashboard -> MUST FAIL with 403
    forbidden_reports = client.get("/api/reports/analyst-activity", headers=analyst_headers)
    assert forbidden_reports.status_code == 403

    # 5. Admin accesses Admin Reporting Dashboard -> MUST SUCCEED with 200
    admin_reports = client.get("/api/reports/analyst-activity?period=month", headers=admin_headers)
    assert admin_reports.status_code == 200
    report_json = admin_reports.json()
    assert "total_cases_reviewed" in report_json
    assert "analyst_breakdown" in report_json
    assert "average_mttr_seconds" in report_json

    # 6. Admin queries list of analysts
    analysts_list = client.get("/api/reports/analysts", headers=admin_headers)
    assert analysts_list.status_code == 200
    assert any(u["username"] == analyst_username for u in analysts_list.json())

    # 7. Admin generates PDF report
    pdf_res = client.get("/api/reports/analyst-activity/pdf?period=month&analyst=all", headers=admin_headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000

def test_multi_tip_aggregation_and_sources():
    from backend.integrations.tip import tip_client

    # 1. Test IP enrichment across 3 TIPs (VirusTotal, AlienVault OTX, AbuseIPDB)
    ip_res = tip_client.enrich_ioc("IP", "198.51.100.45")
    assert ip_res["artifact_type"] == "IP"
    assert len(ip_res["providers"]) == 3  # lab fixture in simulation mode: no live provider contacted
    assert ip_res["virustotal"]["provider"] == "VirusTotal"
    assert ip_res["alienvault_otx"]["provider"] == "AlienVault OTX"
    assert ip_res["abuseipdb"]["provider"] == "AbuseIPDB"
    assert ip_res["threat_score"] >= 70
    assert ip_res["verdict"] == "Malicious"
    assert "AlienVault OTX" in ip_res["consensus"]["sources"]
    assert "VirusTotal v3" in ip_res["consensus"]["sources"]

    # 2. Test File Hash enrichment across 3 TIPs (VirusTotal, AlienVault OTX, ThreatFox)
    hash_res = tip_client.enrich_ioc("Hash", "44d88612fea8a8f36de82e1278abb02f")
    assert hash_res["artifact_type"] == "HASH"
    assert len(hash_res["providers"]) == 3
    assert hash_res["threatfox"]["provider"] == "ThreatFox (abuse.ch)"
    assert hash_res["threat_score"] >= 80

    # 3. Test Non-blocking Background Enrichment Endpoint
    seed_res = client.post("/api/demo/seed")
    assert seed_res.status_code in [200, 201]
    alerts_res = client.get("/api/alerts")
    alerts = alerts_res.json()
    assert len(alerts) > 0
    first_id = alerts[0]["alert_id"]

    bg_res = client.post(f"/api/alerts/{first_id}/enrich-background")
    assert bg_res.status_code == 200
    assert bg_res.json()["status"] == "Queued"
    assert bg_res.json()["alert_id"] == first_id

def test_nvd_integration_and_hotl_execution():
    from backend.integrations.nvd import nvd_client

    # 1. Test CVE extraction & knowledgebase lookup
    cves = nvd_client.extract_cves_from_text("Detected exploit attempt targeting CVE-2024-3094 in sshd process")
    assert "CVE-2024-3094" in cves

    # No NVD key in tests: no live lookup, and no CVSS is invented.
    cve_details = nvd_client.get_vulnerability_details("CVE-2024-3094")
    assert cve_details["cve_id"] == "CVE-2024-3094"
    assert cve_details["status"] == "not_configured"
    assert cve_details["cvss_score"] is None
    assert len(cve_details["hitl_remediation"]) >= 2
    assert cve_details["hotl_action"] == "none"

    # 2. Test Alert NVD vulnerability analysis endpoint
    from backend.database import SessionLocal
    from backend.models import Alert
    db = SessionLocal()
    alert = db.query(Alert).first()
    if not alert:
        client.post("/api/demo/seed")
        alert = db.query(Alert).first()
    alert.title = "Critical RCE via CVE-2024-3094 in liblzma upstream backdoor"
    alert.raw_payload = {"description": "Detected exploit attempt targeting CVE-2024-3094 in sshd process"}
    db.commit()
    first_id = alert.alert_id
    db.close()

    vuln_res = client.get(f"/api/alerts/{first_id}/vulnerabilities")
    assert vuln_res.status_code == 200
    vuln_data = vuln_res.json()
    assert "cves_detected" in vuln_data
    assert "hitl_remediation_steps" in vuln_data
    assert "hotl_autonomous_policy" in vuln_data

    # 3. Test HOTL Programmatic Containment Action Execution
    hotl_res = client.post(f"/api/alerts/{first_id}/vulnerabilities/execute-hotl")
    assert hotl_res.status_code == 200
    hotl_data = hotl_res.json()
    assert hotl_data["status"] == "Success"
    assert hotl_data["action_executed"] == "isolate_endpoint"
    assert hotl_data["new_status"] == "Contained"

def test_playbook_rbac_sec_eng_vs_soc_analyst():
    # 1. Login as root Admin
    admin_login = client.post("/api/auth/login", json={"username": "abunemah", "password": "Admin1"})
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Login as SOC Analyst (L1)
    analyst_login = client.post("/api/auth/login", json={"username": "analyst_rbac_test", "password": "PhantomSOAR1@"})
    analyst_token = analyst_login.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 3. SOC Analyst is ALLOWED to read playbooks (GET)
    read_res = client.get("/api/playbooks", headers=analyst_headers)
    assert read_res.status_code == 200
    assert len(read_res.json()) > 0
    first_pb_id = read_res.json()[0]["playbook_id"]

    # 4. SOC Analyst MUST BE DENIED when attempting to create a playbook (POST) -> 403 Forbidden
    create_payload = {
        "name": "Unauthorized L1 Playbook",
        "target_threat": "Malware",
        "execution_mode": "HOTL",
        "workflow_logic": {"steps": []}
    }
    denied_create = client.post("/api/playbooks", json=create_payload, headers=analyst_headers)
    assert denied_create.status_code == 403
    assert "Playbook modifications are restricted to System Administrators and Security Engineers" in denied_create.json()["detail"]

    # 5. SOC Analyst MUST BE DENIED when attempting to update a playbook (PUT) -> 403 Forbidden
    denied_update = client.put(f"/api/playbooks/{first_pb_id}", json={"name": "Hacked Playbook"}, headers=analyst_headers)
    assert denied_update.status_code == 403
    assert "Playbook modifications are restricted to System Administrators and Security Engineers" in denied_update.json()["detail"]

    # 6. SOC Analyst MUST BE DENIED when attempting to toggle playbook active status (PATCH) -> 403 Forbidden
    denied_toggle = client.patch(f"/api/playbooks/{first_pb_id}/toggle", headers=analyst_headers)
    assert denied_toggle.status_code == 403
    assert "Playbook modifications are restricted to System Administrators and Security Engineers" in denied_toggle.json()["detail"]

    # 7. SOC Analyst MUST BE DENIED when attempting to delete a playbook (DELETE) -> 403 Forbidden
    denied_delete = client.delete(f"/api/playbooks/{first_pb_id}", headers=analyst_headers)
    assert denied_delete.status_code == 403
    assert "Playbook modifications are restricted to System Administrators and Security Engineers" in denied_delete.json()["detail"]

    # 8. Admin / Security Engineer IS ALLOWED to toggle and update playbooks -> 200 OK
    admin_toggle = client.patch(f"/api/playbooks/{first_pb_id}/toggle", headers=admin_headers)
    assert admin_toggle.status_code == 200
    assert "is_active" in admin_toggle.json()

