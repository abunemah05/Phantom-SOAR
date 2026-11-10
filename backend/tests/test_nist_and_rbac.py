import pyotp

from backend.security import hash_password, verify_password, check_nist_password_policy, is_compromised_password


def provision_operator(client, admin_headers, username: str, role: str, password: str = "Correct-Horse-Battery-Staple-26") -> dict:
    """Create an account through the admin API and complete the first-login password change.

    Returns {"user_id", "password", "headers"} where headers carry the session issued by change-password.
    """
    for u in client.get("/api/users", headers=admin_headers).json():
        if u["username"] == username:
            client.delete(f"/api/users/{u['user_id']}", headers=admin_headers)
    created = client.post("/api/users", json={"username": username, "role": role}, headers=admin_headers)
    assert created.status_code == 201, created.text
    change = client.post("/api/auth/change-password", json={
        "username": username,
        "current_password": created.json()["temporary_password"],
        "new_password": password,
    })
    assert change.status_code == 200, change.text
    return {
        "user_id": created.json()["user_id"],
        "password": password,
        "headers": {"Authorization": f"Bearer {change.json()['access_token']}"},
    }


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

    # 4. Compromised passwords blocked (including the passwords earlier releases shipped)
    assert is_compromised_password("password123") is True
    assert is_compromised_password("Admin1") is True
    assert is_compromised_password("PhantomSOAR1@") is True
    valid_comp, _ = check_nist_password_policy("password1234567", mfa_enabled=False)
    assert valid_comp is False


def test_mfa_workflow_and_login_challenge(client, admin_headers):
    op = provision_operator(client, admin_headers, "mfa_operator", "SOC Analyst")
    headers = op["headers"]

    setup_res = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup_res.status_code == 200
    secret = setup_res.json()["secret"]
    assert "otpauth://" in setup_res.json()["provisioning_uri"]

    assert client.post("/api/auth/mfa/verify", json={"code": "000000"}, headers=headers).status_code == 400

    totp = pyotp.TOTP(secret)
    verify_res = client.post("/api/auth/mfa/verify", json={"code": totp.now()}, headers=headers)
    assert verify_res.status_code == 200
    assert verify_res.json()["mfa_enabled"] is True

    # Re-enrolling while MFA is active would silently replace the authenticator.
    assert client.post("/api/auth/mfa/setup", headers=headers).status_code == 400

    login_challenge = client.post("/api/auth/login", json={"username": "mfa_operator", "password": op["password"]})
    assert login_challenge.status_code == 200
    assert login_challenge.json()["mfa_required"] is True
    assert login_challenge.json()["access_token"] == ""

    bad_code = client.post("/api/auth/login", json={"username": "mfa_operator", "password": op["password"], "mfa_code": "000000"})
    assert bad_code.status_code == 401

    login_success = client.post("/api/auth/login", json={
        "username": "mfa_operator", "password": op["password"], "mfa_code": totp.now()
    })
    assert login_success.status_code == 200
    assert login_success.json()["mfa_required"] is False
    assert len(login_success.json()["access_token"]) > 10

    # Password change on an MFA account needs a second factor (code or the operator's own session).
    no_factor = client.post("/api/auth/change-password", json={
        "username": "mfa_operator", "current_password": op["password"], "new_password": "Another-Long-Passphrase-2026"
    })
    assert no_factor.status_code == 400

    # Disabling MFA requires a current code.
    assert client.post("/api/auth/mfa/disable", headers=headers).status_code == 400
    disable_res = client.post("/api/auth/mfa/disable", json={"code": totp.now()}, headers=headers)
    assert disable_res.status_code == 200
    assert disable_res.json()["mfa_enabled"] is False


def test_rbac_admin_vs_soc_analyst(client, admin_headers):
    analyst = provision_operator(client, admin_headers, "analyst_rbac_test", "SOC Analyst Tier 1")
    analyst_headers = analyst["headers"]

    forbidden_users = client.get("/api/users", headers=analyst_headers)
    assert forbidden_users.status_code == 403
    assert "Operation requires SOC Administrator privileges" in forbidden_users.json()["detail"]

    assert client.post("/api/users", json={"username": "intruder_user", "role": "Admin"}, headers=analyst_headers).status_code == 403
    assert client.get("/api/reports/analyst-activity", headers=analyst_headers).status_code == 403
    assert client.get("/api/reports/analyst-activity/pdf", headers=analyst_headers).status_code == 403

    admin_reports = client.get("/api/reports/analyst-activity?period=month", headers=admin_headers)
    assert admin_reports.status_code == 200
    report_json = admin_reports.json()
    for key in ("total_cases_reviewed", "analyst_breakdown", "average_mttr_seconds",
                "containment_by_mode", "mttr_sample_size", "total_containment_actions"):
        assert key in report_json
    assert sum(report_json["containment_by_mode"].values()) == report_json["total_containment_actions"]

    analysts_list = client.get("/api/reports/analysts", headers=admin_headers)
    assert analysts_list.status_code == 200
    assert any(u["username"] == "analyst_rbac_test" for u in analysts_list.json())

    pdf_res = client.get("/api/reports/analyst-activity/pdf?period=month&analyst=all", headers=admin_headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 1000

    # Filenames are sanitised; the analyst filter cannot steer a path.
    custom = client.get("/api/reports/analyst-activity/pdf?period=custom&start_date=2026-01-01&end_date=2026-12-31"
                        "&analyst=../../etc/passwd", headers=admin_headers)
    assert custom.status_code == 200
    assert ".." not in custom.headers["content-disposition"] and "/" not in custom.headers["content-disposition"].split("filename=")[1]


def test_unrecognised_role_has_no_privileges(client, admin_headers):
    from backend.database import SessionLocal
    from backend.models import User
    from backend.security import create_access_token

    provision_operator(client, admin_headers, "role_drift_probe", "SOC Analyst")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "role_drift_probe").first()
        user.role = "Leader of Admin Engineering"  # would have matched the old substring checks
        db.commit()
    finally:
        db.close()
    headers = {"Authorization": f"Bearer {create_access_token({'sub': 'role_drift_probe'})}"}
    assert client.get("/api/users", headers=headers).status_code == 403
    assert client.post("/api/playbooks", headers=headers, json={
        "name": "x", "target_threat": "x", "execution_mode": "HITL", "workflow_logic": {"steps": []}
    }).status_code == 403
    assert client.get("/api/configuration", headers=headers).status_code == 403
    assert client.get("/api/alerts", headers=headers).status_code == 200


def test_multi_tip_aggregation_and_sources(client, admin_headers):
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
    seed_res = client.post("/api/demo/seed", headers=admin_headers)
    assert seed_res.status_code in [200, 201]
    alerts = client.get("/api/alerts", headers=admin_headers).json()
    assert len(alerts) > 0
    first_id = alerts[0]["alert_id"]

    assert client.post(f"/api/alerts/{first_id}/enrich-background").status_code == 401
    bg_res = client.post(f"/api/alerts/{first_id}/enrich-background", headers=admin_headers)
    assert bg_res.status_code == 200
    assert bg_res.json()["status"] == "Queued"
    assert bg_res.json()["alert_id"] == first_id


def test_nvd_integration_and_hotl_execution(client, admin_headers):
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
        client.post("/api/demo/seed", headers=admin_headers)
        alert = db.query(Alert).first()
    alert.title = "Critical RCE via CVE-2024-3094 in liblzma upstream backdoor"
    alert.raw_payload = {"description": "Detected exploit attempt targeting CVE-2024-3094 in sshd process"}
    db.commit()
    first_id = alert.alert_id
    db.close()

    vuln_res = client.get(f"/api/alerts/{first_id}/vulnerabilities", headers=admin_headers)
    assert vuln_res.status_code == 200
    vuln_data = vuln_res.json()
    assert "cves_detected" in vuln_data
    assert "hitl_remediation_steps" in vuln_data
    assert "hotl_autonomous_policy" in vuln_data

    # 3. Without a real CVSS score NVD recommends nothing, so no containment is executed or claimed.
    hotl_res = client.post(f"/api/alerts/{first_id}/vulnerabilities/execute-hotl", headers=admin_headers)
    assert hotl_res.status_code == 409
    assert hotl_res.json()["detail"]["nvd_policy"]["eligible_for_hotl"] is False


def test_playbook_rbac_sec_eng_vs_soc_analyst(client, admin_headers):
    analyst_headers = provision_operator(client, admin_headers, "playbook_analyst_probe", "SOC Analyst Tier 1")["headers"]
    engineer_headers = provision_operator(client, admin_headers, "playbook_engineer_probe", "Security Engineer")["headers"]

    read_res = client.get("/api/playbooks", headers=analyst_headers)
    assert read_res.status_code == 200
    assert len(read_res.json()) > 0
    first_pb_id = read_res.json()[0]["playbook_id"]

    denial = "Playbook modifications are restricted to System Administrators and Security Engineers"
    create_payload = {
        "name": "Unauthorized L1 Playbook",
        "target_threat": "Malware",
        "execution_mode": "HOTL",
        "workflow_logic": {"steps": []}
    }
    denied_create = client.post("/api/playbooks", json=create_payload, headers=analyst_headers)
    assert denied_create.status_code == 403
    assert denial in denied_create.json()["detail"]

    denied_update = client.put(f"/api/playbooks/{first_pb_id}", json={"name": "Hacked Playbook"}, headers=analyst_headers)
    assert denied_update.status_code == 403
    assert denial in denied_update.json()["detail"]

    denied_toggle = client.patch(f"/api/playbooks/{first_pb_id}/toggle", headers=analyst_headers)
    assert denied_toggle.status_code == 403
    assert denial in denied_toggle.json()["detail"]

    denied_delete = client.delete(f"/api/playbooks/{first_pb_id}", headers=analyst_headers)
    assert denied_delete.status_code == 403
    assert denial in denied_delete.json()["detail"]

    # Security engineers and admins may change playbooks; toggle twice to leave the catalogue as it was.
    for headers in (engineer_headers, admin_headers):
        toggled = client.patch(f"/api/playbooks/{first_pb_id}/toggle", headers=headers)
        assert toggled.status_code == 200
        assert "is_active" in toggled.json()
