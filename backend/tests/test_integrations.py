import base64
import json

import httpx
import pytest

from backend import integration_config
from backend.integrations import connector_base
from backend.integrations.edr import edr_client
from backend.integrations.tip import tip_client
from backend.integrations.firewall import firewall_client
from backend.integrations.iam import iam_client
from backend.integrations.itsm import itsm_client

WAZUH = {
    "siem_manager_url": "https://wazuh.test:55000",
    "siem_user": "wazuh-wui",
    "siem_password": "wazuh-secret",
    "siem_verify_tls": "false",
}
OKTA = {"okta_domain": "dev-000.okta.test", "okta_api_token": "okta-token"}
JIRA = {
    "jira_base_url": "https://soc.atlassian.test",
    "jira_email": "soar@corp.test",
    "jira_api_token": "jira-token",
    "jira_project_key": "SOC",
}


@pytest.fixture
def settings(monkeypatch):
    """Per-test integration settings that win over the database and environment."""
    overrides = {}
    original = integration_config.get_setting

    def fake_get_setting(key_name, db=None, default=None):
        if key_name in overrides:
            return overrides[key_name]
        return original(key_name, db=db, default=default)

    monkeypatch.setattr(integration_config, "get_setting", fake_get_setting)
    return overrides


@pytest.fixture
def http(monkeypatch):
    """Route connector HTTP traffic to a handler; returns the list of captured requests."""
    def install(handler):
        calls = []

        def recorder(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return handler(request)

        transport = httpx.MockTransport(recorder)
        monkeypatch.setattr(connector_base, "http_client",
                            lambda verify=True: httpx.Client(transport=transport, timeout=5))
        return calls
    return install


def _basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _wazuh_handler(affected=("004",), failed_items=()):
    def handler(request):
        if request.url.path == "/security/user/authenticate":
            assert request.method == "POST"
            assert request.headers["authorization"] == _basic("wazuh-wui", "wazuh-secret")
            return httpx.Response(200, json={"data": {"token": "jwt-abc"}, "error": 0})
        if request.url.path == "/active-response":
            assert request.method == "PUT"
            assert request.headers["authorization"] == "Bearer jwt-abc"
            return httpx.Response(200, json={
                "data": {"affected_items": list(affected), "total_affected_items": len(affected),
                         "failed_items": list(failed_items)},
                "message": "AR command was sent to all agents", "error": 0,
            })
        return httpx.Response(404)
    return handler


# --- Unconfigured connectors ---------------------------------------------------

def test_unconfigured_connectors_are_simulated_and_send_nothing(settings, http):
    calls = http(lambda request: httpx.Response(500))
    results = [
        edr_client.isolate_endpoint("host-test-99", agent_id="099"),
        edr_client.terminate_process("evil.exe", agent_id="099"),
        firewall_client.block_ip("198.51.100.45", agent_id="099"),
        iam_client.disable_account("jdoe@corp.test"),
        iam_client.revoke_user_sessions("jdoe@corp.test"),
        itsm_client.create_ticket(101, "Ransomware alert", "Test", "High"),
        itsm_client.send_notification("Alert", "Body"),
    ]
    for result in results:
        assert result["status"] == "Simulated"
        assert result["execution_mode"] == "simulated"
        assert result["details"]["simulated"] is True
        assert result["details"]["message"].startswith("SIMULATED")
        assert result["details"]["missing_settings"]
    assert results[5]["ticket_key"] is None
    assert calls == []


def test_unconfigured_connectors_skip_when_simulation_is_off(settings, http):
    settings["simulation_mode"] = "false"
    calls = http(lambda request: httpx.Response(500))
    result = edr_client.isolate_endpoint("host-test-99", agent_id="099")
    assert result["status"] == "Skipped"
    assert result["execution_mode"] == "skipped"
    assert "simulation mode is off" in result["details"]["message"]
    assert calls == []


# --- Wazuh active response ------------------------------------------------------

def test_wazuh_isolate_authenticates_then_sends_active_response(settings, http):
    settings.update(WAZUH)
    calls = http(_wazuh_handler())

    result = edr_client.isolate_endpoint("srv-prod-db01", agent_id="004", alert_context={"phantom_alert_id": 7})

    assert result["status"] == "Success"
    assert result["execution_mode"] == "live"
    assert result["details"]["affected_agents"] == ["004"]
    auth_call, ar_call = calls
    assert auth_call.url.path == "/security/user/authenticate"
    assert ar_call.url.params["agents_list"] == "004"
    body = json.loads(ar_call.content)
    assert body["command"] == "phantom-isolate-host"
    assert body["arguments"] == []
    assert body["alert"]["data"]["hostname"] == "srv-prod-db01"
    assert body["alert"]["data"]["phantom_alert_id"] == 7


def test_wazuh_block_ip_uses_firewall_drop(settings, http):
    settings.update(WAZUH)
    calls = http(_wazuh_handler(affected=("010",)))

    result = firewall_client.block_ip("198.51.100.45", agent_id="010", duration_hours=48)

    assert result["status"] == "Success"
    body = json.loads(calls[1].content)
    assert body["command"] == "firewall-drop"
    assert body["alert"]["data"]["srcip"] == "198.51.100.45"
    assert calls[1].url.params["agents_list"] == "010"
    assert result["details"]["requested"]["duration_hours"] == 48


def test_wazuh_terminate_process_passes_process_arguments(settings, http):
    settings.update(WAZUH)
    calls = http(_wazuh_handler())
    result = edr_client.terminate_process("lockbit3_encryptor.exe", agent_id="004", pid=4242)
    assert result["status"] == "Success"
    body = json.loads(calls[1].content)
    assert body["command"] == "phantom-kill-process"
    assert body["arguments"] == ["lockbit3_encryptor.exe", "4242"]


def test_wazuh_rejected_agent_is_reported_as_failed(settings, http):
    settings.update(WAZUH)
    http(_wazuh_handler(affected=(), failed_items=[{"error": {"code": 1707, "message": "Agent is not active"}, "id": ["004"]}]))
    result = edr_client.isolate_endpoint("srv-prod-db01", agent_id="004")
    assert result["status"] == "Failed"
    assert result["execution_mode"] == "failed"
    assert "Agent is not active" in result["error"]


def test_wazuh_without_agent_id_fails_without_calling(settings, http):
    settings.update(WAZUH)
    calls = http(_wazuh_handler())
    result = edr_client.isolate_endpoint("unknown-host", agent_id=None)
    assert result["status"] == "Failed"
    assert "agent id" in result["error"]
    assert calls == []


def test_wazuh_unreachable_and_bad_credentials_are_failures(settings, http):
    settings.update(WAZUH)

    def unreachable(request):
        raise httpx.ConnectError("connection refused", request=request)

    http(unreachable)
    result = firewall_client.block_ip("198.51.100.45", agent_id="004")
    assert result["status"] == "Failed"
    assert result["error"].startswith("Unreachable")

    http(lambda request: httpx.Response(401, json={"title": "Unauthorized"}))
    result = firewall_client.block_ip("198.51.100.45", agent_id="004")
    assert result["status"] == "Failed"
    assert "HTTP 401" in result["error"]


# --- Okta -----------------------------------------------------------------------

def test_okta_actions_look_up_user_then_call_lifecycle_endpoints(settings, http):
    settings.update(OKTA)

    def handler(request):
        assert request.headers["authorization"] == "SSWS okta-token"
        if request.method == "GET" and request.url.path == "/api/v1/users/jdoe@corp.test":
            return httpx.Response(200, json={"id": "00u1abc", "status": "ACTIVE"})
        if request.url.path.startswith("/api/v1/users/00u1abc/"):
            return httpx.Response(204 if request.method == "DELETE" else 200, json={} if request.method != "DELETE" else None)
        return httpx.Response(404, json={"errorSummary": "Not found"})

    calls = http(handler)

    disabled = iam_client.disable_account("jdoe@corp.test", reason="compromised")
    revoked = iam_client.revoke_user_sessions("jdoe@corp.test")
    reset = iam_client.force_password_reset("jdoe@corp.test")

    for result in (disabled, revoked, reset):
        assert result["status"] == "Success"
        assert result["execution_mode"] == "live"
        assert result["details"]["okta_user_id"] == "00u1abc"
    action_calls = [(c.method, c.url.path) for c in calls if c.method != "GET"]
    assert action_calls == [
        ("POST", "/api/v1/users/00u1abc/lifecycle/suspend"),
        ("DELETE", "/api/v1/users/00u1abc/sessions"),
        ("POST", "/api/v1/users/00u1abc/lifecycle/expire_password"),
    ]
    assert calls[0].url.host == "dev-000.okta.test"


def test_okta_unknown_user_and_api_errors_fail(settings, http):
    settings.update(OKTA)
    http(lambda request: httpx.Response(404, json={"errorSummary": "Not found: Resource not found: ghost"}))
    result = iam_client.disable_account("ghost")
    assert result["status"] == "Failed"
    assert "not found" in result["error"]

    def suspend_rejected(request):
        if request.method == "GET":
            return httpx.Response(200, json={"id": "00u2", "status": "SUSPENDED"})
        return httpx.Response(400, json={"errorSummary": "Cannot suspend a user that is not active"})

    http(suspend_rejected)
    result = iam_client.disable_account("already-suspended")
    assert result["status"] == "Failed"
    assert "Cannot suspend" in result["error"]


# --- Jira / Slack ---------------------------------------------------------------

def test_jira_ticket_uses_the_key_jira_returns(settings, http):
    settings.update(JIRA)

    def handler(request):
        assert request.url.path == "/rest/api/2/issue"
        assert request.headers["authorization"] == _basic("soar@corp.test", "jira-token")
        fields = json.loads(request.content)["fields"]
        assert fields["project"] == {"key": "SOC"}
        assert fields["issuetype"] == {"name": "Task"}
        return httpx.Response(201, json={"id": "10001", "key": "SOC-42", "self": "https://soc.atlassian.test/rest/api/2/issue/10001"})

    http(handler)
    ticket = itsm_client.create_ticket(alert_id=101, summary="Ransomware alert", description="Test", priority="Highest")
    assert ticket["status"] == "Success"
    assert ticket["execution_mode"] == "live"
    assert ticket["ticket_key"] == "SOC-42"
    assert ticket["ticket_url"] == "https://soc.atlassian.test/browse/SOC-42"


def test_jira_retries_without_rejected_priority(settings, http):
    settings.update(JIRA)
    bodies = []

    def handler(request):
        fields = json.loads(request.content)["fields"]
        bodies.append(fields)
        if "priority" in fields:
            return httpx.Response(400, json={"errors": {"priority": "Field 'priority' cannot be set."}})
        return httpx.Response(201, json={"id": "10002", "key": "SOC-43"})

    http(handler)
    ticket = itsm_client.create_ticket(alert_id=102, summary="s", description="d", priority="High")
    assert ticket["ticket_key"] == "SOC-43"
    assert len(bodies) == 2 and "priority" not in bodies[1]
    assert ticket["details"]["notes"]


def test_jira_error_is_failure_without_a_ticket_key(settings, http):
    settings.update(JIRA)
    http(lambda request: httpx.Response(403, text="Forbidden"))
    ticket = itsm_client.create_ticket(alert_id=103, summary="s", description="d")
    assert ticket["status"] == "Failed"
    assert ticket["ticket_key"] is None


def test_jira_webhook_only_claims_no_ticket_key(settings, http):
    settings["jira_webhook_url"] = "https://automation.atlassian.test/hooks/abc"
    calls = http(lambda request: httpx.Response(200, text="ok"))
    ticket = itsm_client.create_ticket(alert_id=104, summary="s", description="d")
    assert ticket["status"] == "Success"
    assert ticket["ticket_key"] is None
    assert json.loads(calls[0].content)["phantom_alert_id"] == 104


def test_slack_notification_posts_to_webhook(settings, http):
    settings["slack_webhook_url"] = "https://hooks.slack.test/services/T/B/X"
    calls = http(lambda request: httpx.Response(200, text="ok"))
    result = itsm_client.send_notification("Alert #5", "Ransomware contained", level="CRITICAL")
    assert result["status"] == "Success"
    assert json.loads(calls[0].content)["text"].startswith("[CRITICAL] Alert #5")


def test_tip_enrichment():
    # Tests run in simulation mode with no API keys: only explicit lab fixtures carry a score.
    res = tip_client.enrich_ioc("IP", "198.51.100.45")
    assert res["artifact_type"] == "IP"
    assert res["threat_score"] > 50
    assert res["verdict"] == "Malicious"
    assert res["simulated"] is True
    assert res["providers"]["abuseipdb"]["status"] == "lab_fixture"

    hash_res = tip_client.enrich_ioc("Hash", "44d88612fea8a8f36de82e1278abb02f")  # EICAR test file
    assert hash_res["threat_score"] >= 80

    unknown = tip_client.enrich_ioc("Domain", "google.com")
    assert unknown["verdict"] == "Unknown"
    assert unknown["threat_score"] == 0
