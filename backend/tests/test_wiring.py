"""Lead-integration tests: settings registry, config validation, HOTL guard, startup checks, maintenance."""
import pytest

from backend import integration_config
from backend.celery_app import run_maintenance
from backend.integrations import connector_base


def save(client, headers, **values):
    configs = []
    for key, value in values.items():
        category = integration_config.INTEGRATION_KEYS[key][0]
        configs.append({"category": category, "key_name": key, "key_value": value, "clear": value == ""})
    return client.post("/api/configuration", headers=headers, json={"configs": configs})


def test_every_setting_read_by_the_integrations_is_registered():
    for key in (
        "vt_requests_per_minute", "vt_requests_per_day", "abuseipdb_daily_limit", "nvd_requests_per_30s",
        "tip_max_wait_seconds", "tip_malicious_threshold", "wazuh_ca_bundle", "wazuh_ar_script_prefix",
        "wazuh_windows_agent_ids", "wazuh_firewall_agent_ids", "wazuh_default_block_hours",
        "wazuh_ar_block_command", "okta_login_domain", "jira_api_version", "jira_issue_type", "require_mfa_for_admin",
    ):
        assert key in integration_config.INTEGRATION_KEYS, key


def test_configuration_lists_new_keys_and_validates_numbers(client, admin_headers):
    listing = client.get("/api/configuration", headers=admin_headers).json()
    assert "vt_requests_per_minute" in listing["TIP"] and "wazuh_ca_bundle" in listing["SIEM"]
    assert "jira_issue_type" in listing["ITSM"] and "okta_login_domain" in listing["IAM"]

    assert save(client, admin_headers, vt_requests_per_minute="abc").status_code == 400
    assert save(client, admin_headers, vt_requests_per_minute="-3").status_code == 400
    assert save(client, admin_headers, vt_requests_per_minute="2.5").status_code == 400
    assert save(client, admin_headers, tip_critical_threshold="101").status_code == 400
    assert save(client, admin_headers, jira_api_version="4").status_code == 400
    assert save(client, admin_headers, wazuh_default_block_hours="721").status_code == 400
    ok = save(client, admin_headers, vt_requests_per_minute="6", wazuh_default_block_hours="12", jira_api_version="3")
    assert ok.status_code == 200
    assert integration_config.get_setting("vt_requests_per_minute") == "6"
    save(client, admin_headers, vt_requests_per_minute="", wazuh_default_block_hours="", jira_api_version="")


def test_hotl_cannot_be_enabled_through_the_settings_save_without_protected_assets(client, admin_headers):
    save(client, admin_headers, protected_hosts="", protected_users="", protected_ips="")
    refused = save(client, admin_headers, hotl_enabled="true")
    assert refused.status_code == 409
    assert refused.json()["detail"]["blockers"]
    assert integration_config.get_bool("hotl_enabled") is False  # nothing was saved

    both = save(client, admin_headers, protected_hosts="dc01.corp.example", protected_users="breakglass", hotl_enabled="true")
    assert both.status_code == 200
    assert integration_config.get_bool("hotl_enabled") is True
    save(client, admin_headers, hotl_enabled="false")
    save(client, admin_headers, protected_hosts="", protected_users="")


def test_saving_settings_clears_threat_intel_caches(client, admin_headers, monkeypatch):
    from backend.integrations import nvd, tip

    cleared = []
    monkeypatch.setattr(tip, "clear_cache", lambda: cleared.append("tip"))
    monkeypatch.setattr(nvd, "clear_cache", lambda: cleared.append("nvd"))
    assert save(client, admin_headers, tip_max_wait_seconds="3").status_code == 200
    assert cleared == ["tip", "nvd"]
    cleared.clear()
    assert save(client, admin_headers, tip_max_wait_seconds="3").status_code == 200  # unchanged -> no clear
    assert cleared == []
    save(client, admin_headers, tip_max_wait_seconds="")


def test_security_tables_exist_and_ingest_token_router_is_mounted(client, admin_headers):
    assert client.get("/api/ingest-tokens", headers=admin_headers).status_code == 200
    assert client.get("/api/ingest-tokens").status_code == 401


def test_maintenance_runs_every_step_and_survives_a_failing_one(monkeypatch):
    summary = run_maintenance()
    assert set(summary) == {"expired_logs_purged", "expired_revocations_purged", "stale_alerts_resumed"}
    assert all(not str(v).startswith("error") for v in summary.values())

    import backend.security as security

    monkeypatch.setattr(security, "purge_expired_revocations", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    summary = run_maintenance()
    assert summary["expired_revocations_purged"].startswith("error")
    assert not str(summary["expired_logs_purged"]).startswith("error")


def test_celery_beat_schedules_maintenance():
    from backend.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["phantom-maintenance"]
    assert entry["task"] == "tasks.maintenance"


def test_request_with_retry_can_exclude_429(monkeypatch):
    import httpx

    monkeypatch.setattr(connector_base, "sleep", lambda s: None)
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": "1"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        resp = connector_base.request_with_retry(
            client, "GET", "https://x.test/", retry_statuses=connector_base.RETRY_STATUSES - {429})
    assert resp.status_code == 429 and len(calls) == 1


def test_apply_rate_limit_accepts_a_duration():
    from backend.engine.actions import ACTION_CATALOG

    assert ACTION_CATALOG["apply_rate_limit"]["params"]["duration_hours"]["maximum"] == 720


def test_dashboard_metrics_report_simulated_alerts_separately(client, admin_headers):
    metrics = client.get("/api/alerts/metrics/dashboard", headers=admin_headers)
    assert metrics.status_code == 200
    assert "simulated_alerts" in metrics.json()


def test_alert_detail_never_calls_nvd_live(client, admin_headers, ingest_headers, monkeypatch):
    from backend.integrations import nvd

    seen = []
    original = nvd.nvd_client.get_vulnerability_details

    def spy(cve, *args, **kwargs):
        seen.append(kwargs.get("allow_live"))
        return original(cve, *args, **kwargs)

    monkeypatch.setattr(nvd.nvd_client, "get_vulnerability_details", spy)
    monkeypatch.setattr(nvd.nvd_client, "refresh_alert_vulnerabilities", lambda alert_id: None)
    res = client.post("/api/webhooks/wazuh", headers=ingest_headers, json={
        "rule": {"id": "99001", "level": 7, "description": "Exploit attempt CVE-2021-44228 detected"},
        "agent": {"id": "001", "name": "web01"}, "full_log": "CVE-2021-44228",
    })
    assert res.status_code in (200, 201), res.text
    alert_id = res.json().get("alert_id") or res.json().get("id")
    detail = client.get(f"/api/alerts/{alert_id}", headers=admin_headers)
    assert detail.status_code == 200
    assert seen and all(flag is False for flag in seen)
