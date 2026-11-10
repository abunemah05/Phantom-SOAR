import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import integration_config
from backend.crud import create_alert, create_ioc_artifact, create_playbook
from backend.database import Base
from backend.engine import runner as runner_module
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS
from backend.engine.runner import (
    NoPlaybookError,
    approve_and_contain_alert,
    build_triage_summary,
    close_pending_actions,
    evaluate_execution_mode,
    extract_mitre,
    match_playbook,
    process_alert,
)
from backend.models import ContainmentAction, PlaybookExecution


def lab_evidence(score=95):
    return {
        "abuseipdb": {"provider": "abuseipdb", "status": "lab_fixture", "threat_score": score,
                      "verdict": "Malicious", "summary": {}, "error": None, "queried_at": None},
        "virustotal": {"provider": "virustotal", "status": "not_configured", "threat_score": None,
                       "verdict": None, "summary": {}, "error": None, "queried_at": None},
    }


NO_EVIDENCE = {
    "virustotal": {"provider": "virustotal", "status": "not_configured", "threat_score": None, "verdict": None},
    "abuseipdb": {"provider": "abuseipdb", "status": "not_found", "threat_score": None, "verdict": None},
}


def ransomware_payload(srcip="198.51.100.45"):
    return {
        "rule": {"id": "100201", "level": 10, "description": "Ransomware activity: bulk file encryption",
                 "mitre": {"id": ["T1486"], "tactic": ["Impact"], "technique": ["Data Encrypted for Impact"]}},
        "agent": {"id": "004", "name": "srv-prod-db01", "ip": "10.0.4.15"},
        "data": {"process": "lockbit3_encryptor.exe", "srcip": srcip, "srcuser": "svc_sqladmin"},
    }


@pytest.fixture
def settings(monkeypatch):
    overrides = {"hotl_enabled": "true", "simulation_mode": "true", "protected_hosts": "",
                 "protected_users": "", "protected_ips": ""}
    original = integration_config.get_setting

    def fake_get_setting(key_name, db=None, default=None):
        if key_name in overrides:
            return overrides[key_name]
        return original(key_name, db=db, default=default)

    monkeypatch.setattr(integration_config, "get_setting", fake_get_setting)
    return overrides


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Isolated database with the catalog playbooks; the runner opens its sessions here too."""
    engine = create_engine(f"sqlite:///{tmp_path / 'runner.db'}")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(runner_module, "SessionLocal", Session)
    session = Session()
    for pb in PRECONFIGURED_PLAYBOOKS:
        create_playbook(session, pb)
    yield session
    session.close()


def make_alert(db, payload, severity="High", ioc=None, minutes_ago=0):
    alert = create_alert(db, {
        "rule_id": f"WAZUH-{payload['rule']['id']}",
        "source": "Wazuh SIEM",
        "severity": severity,
        "status": "New",
        "raw_payload": payload,
        "created_at": datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    })
    if ioc:
        create_ioc_artifact(db, alert.alert_id, **ioc)
    return alert


def actions_for(db, alert_id):
    db.expire_all()
    return db.query(ContainmentAction).filter(ContainmentAction.alert_id == alert_id).order_by(ContainmentAction.action_id).all()


def test_unknown_ioc_alert_does_not_auto_contain(db, settings):
    alert = make_alert(db, ransomware_payload(srcip="8.8.8.8"), severity="High", ioc={
        "artifact_type": "IP", "value": "8.8.8.8", "threat_score": 0, "verdict": "Unknown",
        "enrichment_status": "not_configured", "tip_results": NO_EVIDENCE,
    })

    result = process_alert(alert.alert_id)

    assert result["mode"] == "HITL"
    assert result["status"] == "Triaged"
    assert result["playbook"] == "Ransomware Outbreak Containment"
    assert "No confirmed evidence" in result["reasons"][0]
    assert actions_for(db, alert.alert_id) == []


def test_malicious_verdict_without_provider_evidence_is_not_evidence(db, settings):
    alert = make_alert(db, ransomware_payload(), ioc={
        "artifact_type": "IP", "value": "198.51.100.45", "threat_score": 95, "verdict": "Malicious",
    })
    assert process_alert(alert.alert_id)["mode"] == "HITL"


def test_lab_malicious_ransomware_runs_hotl_playbook_steps(db, settings):
    alert = make_alert(db, ransomware_payload(), severity="High", minutes_ago=2, ioc={
        "artifact_type": "IP", "value": "198.51.100.45", "threat_score": 95, "verdict": "Malicious",
        "enrichment_status": "enriched", "tip_results": lab_evidence(),
    })

    result = process_alert(alert.alert_id)

    assert result["mode"] == "HOTL"
    assert result["status"] == "Contained"
    assert result["execution_status"] == "Completed (HOTL, simulated)"
    assert result["simulated"] is True
    assert any("lab fixture" in e for e in result["evidence"])

    records = actions_for(db, alert.alert_id)
    performed = [(r.action_type, r.target, r.connector) for r in records]
    assert performed == [
        ("isolate_endpoint", "srv-prod-db01", "edr"),
        ("terminate_process", "lockbit3_encryptor.exe", "edr"),
        ("block_ip", "198.51.100.45", "firewall"),  # the host's own 10.0.4.15 is never a block target
        ("revoke_user_sessions", "svc_sqladmin", "iam"),
    ]
    assert all(r.status == "Simulated" and r.execution_mode == "simulated" for r in records)
    assert all(r.executed_by == "HOTL Engine" for r in records)

    # MTTR is the real time since the alert was created (about two minutes), not a padded constant.
    assert 110 <= result["mttr_seconds"] <= 300
    assert os.path.exists(result["pdf_path"])

    # Re-processing is a no-op.
    again = process_alert(alert.alert_id)
    assert again["mode"] is None
    assert len(actions_for(db, alert.alert_id)) == len(records)


def test_critical_telemetry_counts_as_evidence(db, settings):
    alert = make_alert(db, ransomware_payload(srcip="8.8.8.8"), severity="Critical", ioc={
        "artifact_type": "IP", "value": "8.8.8.8", "verdict": "Unknown", "tip_results": NO_EVIDENCE,
    })
    result = process_alert(alert.alert_id)
    assert result["mode"] == "HOTL"
    assert "Telemetry severity is Critical" in result["evidence"]


def test_hotl_switched_off_routes_to_hitl(db, settings):
    settings["hotl_enabled"] = "false"
    alert = make_alert(db, ransomware_payload(), ioc={
        "artifact_type": "IP", "value": "198.51.100.45", "threat_score": 95, "verdict": "Malicious",
        "tip_results": lab_evidence(),
    })

    result = process_alert(alert.alert_id)

    assert result["mode"] == "HITL"
    assert "switched off" in result["reasons"][0]
    assert actions_for(db, alert.alert_id) == []


def test_hitl_playbook_waits_then_approval_executes_steps(db, settings):
    payload = {
        "rule": {"id": "100340", "level": 6, "description": "Phishing: credential-harvesting link",
                 "mitre": {"id": ["T1566.002"]}},
        "agent": {"id": "002", "name": "mail-relay-edge", "ip": "10.0.1.20"},
        "data": {"srcip": "192.0.2.77", "dstuser": "jdoe@corp.example"},
    }
    alert = make_alert(db, payload, severity="Medium", minutes_ago=1, ioc={
        "artifact_type": "IP", "value": "192.0.2.77", "threat_score": 45, "verdict": "Suspicious",
        "tip_results": lab_evidence(45),
    })

    routed = process_alert(alert.alert_id)
    assert routed["mode"] == "HITL"
    assert routed["playbook"] == "Spearphishing Email & Credential Harvesting"
    assert actions_for(db, alert.alert_id) == []

    result = approve_and_contain_alert(db, alert.alert_id, approved_by="analyst_omar")

    assert result["status"] == "Contained"
    assert result["execution_status"] == "Completed (HITL, simulated)"
    records = actions_for(db, alert.alert_id)
    assert [(r.action_type, r.target) for r in records] == [
        ("revoke_user_sessions", "jdoe@corp.example"),
        ("block_ip", "192.0.2.77"),
    ]
    assert all(r.executed_by == "analyst_omar" for r in records)
    assert any("approval gate satisfied" in n for n in result["notes"])
    assert result["mttr_seconds"] >= 55

    executions = db.query(PlaybookExecution).filter(PlaybookExecution.alert_id == alert.alert_id).all()
    assert len(executions) == 1  # the pending execution was completed, not duplicated
    assert executions[0].status == "Completed (HITL, simulated)"


def test_private_ip_block_is_held_for_approval(db, settings):
    alert = make_alert(db, ransomware_payload(srcip="10.9.9.9"), severity="Critical")

    result = process_alert(alert.alert_id)

    assert result["mode"] == "HOTL"
    assert result["status"] == "Triaged"
    assert result["execution_status"] == "Awaiting Approval (HOTL)"
    held = [r for r in actions_for(db, alert.alert_id) if r.status == "Awaiting Approval"]
    assert [(r.action_type, r.target, r.execution_mode) for r in held] == [("block_ip", "10.9.9.9", "blocked")]

    approved = approve_and_contain_alert(db, alert.alert_id, approved_by="lead")
    assert approved["status"] == "Contained"
    new_actions = approved["actions"]
    assert [(a["action_type"], a["target"]) for a in new_actions] == [("block_ip", "10.9.9.9")]
    assert {d["action"] for d in approved["already_done"]} == {"isolate_endpoint", "terminate_process", "revoke_user_sessions"}

    db.expire_all()
    resolved = db.get(ContainmentAction, held[0].action_id)
    assert resolved.status == "Approved"
    assert resolved.details["resolution"]["by"] == "lead"
    assert resolved.details["resolution"]["executed_action_id"] == new_actions[0]["action_id"]


def test_dismissing_declines_held_actions(db, settings):
    alert = make_alert(db, ransomware_payload(srcip="10.9.9.9"), severity="Critical")
    process_alert(alert.alert_id)
    db.expire_all()
    alert = db.get(type(alert), alert.alert_id)

    assert close_pending_actions(db, alert, by="lead") == 1
    statuses = {r.action_type: r.status for r in actions_for(db, alert.alert_id)}
    assert statuses["block_ip"] == "Declined"
    assert close_pending_actions(db, alert, by="lead") == 0


def test_protected_host_is_blocked_for_the_playbook(db, settings):
    settings["protected_hosts"] = "srv-prod-*"
    alert = make_alert(db, ransomware_payload(), severity="Critical")

    result = process_alert(alert.alert_id)

    by_action = {r.action_type: r for r in actions_for(db, alert.alert_id)}
    assert by_action["isolate_endpoint"].status == "Blocked"
    assert by_action["isolate_endpoint"].execution_mode == "blocked"
    assert "protected" in " ".join(by_action["isolate_endpoint"].details["reasons"])
    assert by_action["terminate_process"].status == "Blocked"
    assert by_action["block_ip"].status == "Simulated"
    assert result["execution_status"] == "Partial (HOTL, simulated)"


def test_unmatched_alert_goes_to_analyst_and_needs_a_chosen_playbook(db, settings):
    payload = {"rule": {"id": "99901", "level": 13, "description": "Cobalt Strike beacon detected",
                        "mitre": {"id": ["T1071"]}},
               "agent": {"id": "010", "name": "workstation-10"}, "data": {"srcip": "203.0.113.50"}}
    alert = make_alert(db, payload, severity="Critical")

    result = process_alert(alert.alert_id)
    assert result["mode"] == "HITL"
    assert result["playbook"] is None
    assert "No active playbook" in result["reasons"][0]

    with pytest.raises(NoPlaybookError):
        approve_and_contain_alert(db, alert.alert_id, approved_by="lead")

    ransomware = match_playbook(db, make_alert(db, ransomware_payload()))
    chosen = approve_and_contain_alert(db, alert.alert_id, approved_by="lead", playbook_id=ransomware.playbook_id)
    assert chosen["playbook"] == "Ransomware Outbreak Containment"
    assert {a["action_type"] for a in chosen["actions"]} >= {"isolate_endpoint", "block_ip"}


def test_playbook_matching_and_mitre_mapping(db, settings):
    by_keyword = make_alert(db, {"rule": {"id": "5712", "level": 10,
                                          "description": "sshd: brute force trying to get access to the system"}})
    assert match_playbook(db, by_keyword).target_threat == "Brute Force"

    by_mitre = make_alert(db, {"rule": {"id": "1", "level": 5, "description": "Suspicious file on server",
                                        "mitre": {"id": ["T1505.003"]}}})
    assert match_playbook(db, by_mitre).target_threat == "WebShell"

    nothing = make_alert(db, {"rule": {"id": "2", "level": 3, "description": "User logged in"}})
    assert match_playbook(db, nothing) is None
    assert extract_mitre(nothing, None) == {"id": [], "tactic": [], "technique": [], "source": None}

    mapped = extract_mitre(by_keyword, match_playbook(db, by_keyword))
    assert mapped["id"] == ["T1110"] and mapped["source"] == "playbook"
    assert extract_mitre(by_mitre, None)["source"] == "telemetry"


def test_legacy_playbook_names_still_execute(db, settings):
    legacy = create_playbook(db, {
        "name": "Legacy Brute Force", "target_threat": "Legacy Brute", "execution_mode": "HITL",
        "workflow_logic": {"steps": [{"action": "create_jira_ticket", "priority": "High"},
                                     {"action": "terminate_process", "params": {"target": "encryptor.exe"}}]},
    })
    alert = make_alert(db, {"rule": {"id": "3", "level": 5, "description": "Legacy brute attempt"}})

    result = approve_and_contain_alert(db, alert.alert_id, approved_by="lead", playbook_id=legacy.playbook_id)

    records = actions_for(db, alert.alert_id)
    assert [(r.action_type, r.status) for r in records] == [("create_ticket", "Simulated"), ("terminate_process", "Skipped")]
    assert records[1].details["reason"] == "no_target"  # hardcoded legacy targets are ignored
    assert any("ignored unsupported params" in n for n in result["notes"])
    assert result["status"] == "Triaged"  # a ticket alone does not contain anything
    assert result["execution_status"] == "No Containment (HITL)"


def test_triage_summary_is_factual(db, settings):
    alert = make_alert(db, ransomware_payload(srcip="8.8.8.8"), ioc={
        "artifact_type": "IP", "value": "8.8.8.8", "verdict": "Unknown",
        "enrichment_status": "not_configured", "tip_results": NO_EVIDENCE,
    })
    playbook = match_playbook(db, alert)
    summary = build_triage_summary(db, alert, alert.ioc_artifacts, playbook)
    assert "1 Unknown" in summary
    assert "could not be checked" in summary
    assert "Ransomware Outbreak Containment" in summary
    assert "No confirmed evidence" in summary
    assert evaluate_execution_mode(db, alert, alert.ioc_artifacts, playbook)["mode"] == "HITL"
