import json

import httpx
import pytest

from backend import integration_config
from backend.crud import create_alert, create_ioc_artifact
from backend.engine import actions
from backend.engine.actions import (
    ACTION_CATALOG,
    execute_action,
    list_actions,
    record_policy_block,
    resolve_action_name,
    validate_workflow_steps,
)
from backend.engine.policy import PolicyDecision, evaluate_action, get_alert_entities
from backend.integrations import connector_base

RANSOMWARE_PAYLOAD = {
    "rule": {"id": "100201", "level": 14, "description": "Ransomware activity: bulk encryption",
             "mitre": {"id": ["T1486"], "tactic": ["Impact"], "technique": ["Data Encrypted for Impact"]}},
    "agent": {"id": "004", "name": "srv-prod-db01", "ip": "10.0.4.15"},
    "data": {"process": "lockbit3_encryptor.exe", "srcip": "198.51.100.45", "dstip": "127.0.0.1",
             "srcuser": "svc_sqladmin", "file_hash": "44D88612FEA8A8F36DE82E1278ABB02F",
             "file": "C:\\Shares\\Data\\invoice.lockbit"},
}


@pytest.fixture
def settings(monkeypatch):
    overrides = {}
    original = integration_config.get_setting

    def fake_get_setting(key_name, db=None, default=None):
        if key_name in overrides:
            return overrides[key_name]
        return original(key_name, db=db, default=default)

    monkeypatch.setattr(integration_config, "get_setting", fake_get_setting)
    overrides.update({"hotl_enabled": "true", "simulation_mode": "true", "protected_hosts": "",
                      "protected_users": "", "protected_ips": "", "agent_autonomy": "recommend_only",
                      "agent_min_confidence": "0.85"})
    return overrides


@pytest.fixture
def db(client):
    from backend.database import SessionLocal
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def alert(db):
    record = create_alert(db, {"rule_id": "TEST-POLICY-RANSOM", "source": "Wazuh SIEM", "severity": "High",
                               "status": "Triaged", "raw_payload": RANSOMWARE_PAYLOAD})
    create_ioc_artifact(db, record.alert_id, "IP", "198.51.100.45", 95, verdict="Malicious")
    create_ioc_artifact(db, record.alert_id, "Domain", "C2-Beacon.lab.example", 92, verdict="Malicious")
    db.refresh(record)
    return record


# --- Catalog ----------------------------------------------------------------------

def test_catalog_covers_required_actions():
    required = {"isolate_endpoint", "unisolate_endpoint", "terminate_process", "quarantine_file", "block_ip",
                "unblock_ip", "apply_rate_limit", "disable_account", "revoke_user_sessions",
                "force_password_reset", "create_ticket", "send_notification"}
    assert required <= set(ACTION_CATALOG)
    for item in list_actions():
        assert item["connector"] in {"edr", "firewall", "iam", "itsm"}
        assert item["target_type"] in {"host", "ip", "user", "file", "process", "none"}
        assert item["impact"] in {"low", "medium", "high"}
        assert isinstance(item["reversible"], bool) and item["description"]
    assert resolve_action_name("create_jira_ticket") == "create_ticket"
    assert resolve_action_name("rm_rf") is None


def test_workflow_validation():
    assert validate_workflow_steps({"steps": [
        {"action": "isolate_endpoint"}, {"action": "await_analyst_approval"},
        {"action": "create_jira_ticket", "params": {"priority": "High"}}, {"action": "generate_report"},
        {"action": "block_ip", "params": "duration: 24"},
    ]}) == []
    errors = validate_workflow_steps({"steps": [{"action": "purge_email_inbox"}, {"action": "block_ip", "params": {"ttl": 1}}]})
    assert any("purge_email_inbox" in e for e in errors)
    assert any("ttl" in e for e in errors)
    assert validate_workflow_steps({"steps": "isolate"}) == ["workflow_logic.steps must be a list."]


# --- Entities ---------------------------------------------------------------------

def test_alert_entities_from_wazuh_payload_and_iocs(alert):
    entities = get_alert_entities(alert)
    assert entities["hosts"] == ["srv-prod-db01"]
    assert entities["ips"] == ["10.0.4.15", "198.51.100.45", "127.0.0.1"]
    assert entities["users"] == ["svc_sqladmin"]
    assert entities["processes"] == ["lockbit3_encryptor.exe"]
    assert entities["files"] == ["C:\\Shares\\Data\\invoice.lockbit"]
    assert entities["hashes"] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert entities["domains"] == ["c2-beacon.lab.example"]


def test_entities_from_edr_payload():
    payload = {"raw_payload": {"agent": {"hostname": "WIN-01", "ip": "10.1.1.5"},
                               "process": {"name": "mimikatz.exe", "pid": 812}, "user": "CORP\\jdoe",
                               "hash": "abc123"}}
    entities = get_alert_entities(payload)
    assert entities["hosts"] == ["WIN-01"]
    assert entities["processes"] == ["mimikatz.exe"]
    assert entities["users"] == ["CORP\\jdoe"]
    assert entities["hashes"] == ["abc123"]


# --- Policy -------------------------------------------------------------------------

def test_unknown_action_and_missing_target_are_denied(settings, db, alert):
    decision = evaluate_action(db, alert, "format_disk", "srv-prod-db01", actor="analyst")
    assert isinstance(decision, PolicyDecision)
    assert decision.allowed is False and "Unknown action" in decision.reasons[0]
    assert evaluate_action(db, alert, "isolate_endpoint", None, actor="analyst").allowed is False
    assert evaluate_action(db, alert, "block_ip", "not-an-ip", actor="analyst").allowed is False
    assert evaluate_action(db, alert, "block_ip", "198.51.100.45", {"direction": "sideways"}, actor="analyst").allowed is False
    assert evaluate_action(db, alert, "block_ip", "198.51.100.45", actor="robot").allowed is False


def test_agent_target_must_be_an_alert_entity(settings, db, alert):
    other = evaluate_action(db, alert, "isolate_endpoint", "ceo-laptop", actor="agent", confidence=0.99)
    assert other.allowed is False
    assert "not a host named in alert" in other.reasons[0]

    own = evaluate_action(db, alert, "isolate_endpoint", "SRV-PROD-DB01", actor="agent", confidence=0.99)
    assert own.allowed is True
    assert own.requires_approval is True  # recommend_only

    assert evaluate_action(db, alert, "block_ip", "203.0.113.9", actor="agent", confidence=0.99).allowed is False
    # Playbooks and analysts are not limited to the alert's entities.
    assert evaluate_action(db, alert, "block_ip", "203.0.113.9", actor="playbook").allowed is True


def test_protected_assets(settings, db, alert):
    settings.update({"protected_hosts": "srv-prod-*", "protected_users": "svc_sqladmin", "protected_ips": "198.51.100.0/24"})

    for actor in ("agent", "playbook"):
        assert evaluate_action(db, alert, "isolate_endpoint", "srv-prod-db01", actor=actor, confidence=0.99).allowed is False
        # EDR actions on the protected host are denied too, whatever the target.
        assert evaluate_action(db, alert, "terminate_process", "lockbit3_encryptor.exe", actor=actor, confidence=0.99).allowed is False
        assert evaluate_action(db, alert, "disable_account", "svc_sqladmin", actor=actor, confidence=0.99).allowed is False
        assert evaluate_action(db, alert, "block_ip", "198.51.100.45", actor=actor, confidence=0.99).allowed is False

    analyst = evaluate_action(db, alert, "isolate_endpoint", "srv-prod-db01", actor="analyst")
    assert analyst.allowed is True and analyst.requires_approval is False
    assert any("protected" in r for r in analyst.reasons)


def test_ip_rules(settings, db, alert):
    for ip in ("127.0.0.1", "::1", "169.254.10.10", "224.0.0.5", "0.0.0.0", "240.0.0.1"):
        decision = evaluate_action(db, alert, "block_ip", ip, actor="analyst")
        assert decision.allowed is False, ip
        assert "never blocked" in decision.reasons[0]

    private = evaluate_action(db, alert, "block_ip", "10.0.4.15", actor="playbook")
    assert private.allowed is True and private.requires_approval is True
    assert evaluate_action(db, alert, "apply_rate_limit", "192.168.1.20", actor="playbook").requires_approval is True
    assert evaluate_action(db, alert, "block_ip", "10.0.4.15", actor="analyst").requires_approval is False

    public = evaluate_action(db, alert, "block_ip", "198.51.100.45", actor="playbook")
    assert public.allowed is True and public.requires_approval is False
    # Unblocking is never refused for address class.
    assert evaluate_action(db, alert, "unblock_ip", "127.0.0.1", actor="analyst").allowed is True


def test_hotl_disabled_requires_approval_for_automation(settings, db, alert):
    settings["hotl_enabled"] = "false"
    assert evaluate_action(db, alert, "block_ip", "198.51.100.45", actor="playbook").requires_approval is True
    assert evaluate_action(db, alert, "block_ip", "198.51.100.45", actor="analyst").requires_approval is False


def test_agent_autonomy_levels(settings, db, alert):
    def decide(action, target, confidence):
        return evaluate_action(db, alert, action, target, actor="agent", confidence=confidence)

    settings["agent_autonomy"] = "recommend_only"
    assert decide("create_ticket", None, 0.99).requires_approval is True

    settings["agent_autonomy"] = "low_impact"
    assert decide("create_ticket", None, 0.9).requires_approval is False
    assert decide("create_ticket", None, 0.5).requires_approval is True
    assert decide("block_ip", "198.51.100.45", 0.95).requires_approval is True
    assert decide("create_ticket", None, None).requires_approval is True

    settings["agent_autonomy"] = "policy"
    assert decide("block_ip", "198.51.100.45", 0.9).requires_approval is False
    assert decide("block_ip", "198.51.100.45", 0.6).requires_approval is True
    assert decide("isolate_endpoint", "srv-prod-db01", 0.99).requires_approval is True  # high impact
    assert decide("block_ip", "10.0.4.15", 0.99).requires_approval is True  # private range

    settings["agent_autonomy"] = "yolo"  # unknown value falls back to recommend_only
    assert decide("create_ticket", None, 0.99).requires_approval is True


# --- execute_action -------------------------------------------------------------------

def test_execute_action_simulated_when_unconfigured(settings, db, alert):
    record = execute_action(db, alert, "block_ip", "198.51.100.45", {"duration_hours": 24}, executed_by="tester")
    assert record.status == "Simulated"
    assert record.execution_mode == "simulated"
    assert record.connector == "firewall"
    assert record.target == "198.51.100.45"
    assert record.executed_by == "tester"
    assert record.details["details"]["message"].startswith("SIMULATED")
    assert record.details["params"] == {"duration_hours": 24}

    ticket = execute_action(db, alert, "create_jira_ticket", "ignored", executed_by="tester")
    assert ticket.action_type == "create_ticket"
    assert ticket.target == f"Alert #{alert.alert_id}"
    assert ticket.status == "Simulated"


def test_execute_action_skipped_when_simulation_off(settings, db, alert):
    settings["simulation_mode"] = "false"
    record = execute_action(db, alert, "isolate_endpoint", "srv-prod-db01")
    assert record.status == "Skipped"
    assert record.execution_mode == "skipped"


def test_execute_action_live_uses_alert_agent_id(settings, db, alert, monkeypatch):
    settings.update({"siem_manager_url": "https://wazuh.test:55000", "siem_user": "u", "siem_password": "p"})
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/authenticate"):
            return httpx.Response(200, json={"data": {"token": "t"}})
        return httpx.Response(200, json={"data": {"affected_items": ["004"], "failed_items": []}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(connector_base, "http_client", lambda verify=True: httpx.Client(transport=transport))

    record = execute_action(db, alert, "isolate_endpoint", "srv-prod-db01")
    assert record.status == "Success" and record.execution_mode == "live"
    assert calls[1].url.params["agents_list"] == "004"
    assert json.loads(calls[1].content)["alert"]["data"]["phantom_alert_id"] == alert.alert_id

    # A host that is not the alert's agent has no known agent id: failed, not pretended.
    other = execute_action(db, alert, "isolate_endpoint", "some-other-host")
    assert other.status == "Failed" and other.execution_mode == "failed"


def test_execute_action_never_raises_on_connector_error(settings, db, alert, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("driver exploded")

    monkeypatch.setattr(actions.firewall_client, "block_ip", boom)
    record = execute_action(db, alert, "block_ip", "198.51.100.45")
    assert record.status == "Failed"
    assert record.execution_mode == "failed"
    assert "driver exploded" in record.details["error"]

    with pytest.raises(ValueError):
        execute_action(db, alert, "format_disk", "srv-prod-db01")


def test_record_policy_block(settings, db, alert):
    blocked = record_policy_block(db, alert, "block_ip", "127.0.0.1", PolicyDecision(False, False, ["loopback"]))
    assert blocked.status == "Blocked" and blocked.execution_mode == "blocked"
    assert blocked.details["reasons"] == ["loopback"]
    held = record_policy_block(db, alert, "block_ip", "10.0.4.15", PolicyDecision(True, True, ["private"]))
    assert held.status == "Awaiting Approval" and held.execution_mode == "blocked"


# --- Playbook API validation ------------------------------------------------------------

def test_playbook_api_rejects_unknown_actions(client, admin_headers):
    bad = {"name": "Bad", "target_threat": "X", "execution_mode": "HOTL",
           "workflow_logic": {"steps": [{"action": "launch_missiles"}]}}
    res = client.post("/api/playbooks", json=bad, headers=admin_headers)
    assert res.status_code == 422
    assert "launch_missiles" in json.dumps(res.json())

    bad_mode = {"name": "Bad", "target_threat": "X", "execution_mode": "YOLO",
                "workflow_logic": {"steps": [{"action": "block_ip"}]}}
    assert client.post("/api/playbooks", json=bad_mode, headers=admin_headers).status_code == 422

    catalog = client.get("/api/playbooks/actions", headers=admin_headers)
    assert catalog.status_code == 200
    assert {a["name"] for a in catalog.json()["actions"]} >= {"block_ip", "isolate_endpoint"}
