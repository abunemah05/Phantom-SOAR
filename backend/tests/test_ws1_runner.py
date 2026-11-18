"""WS1: simulation never counts as containment, idempotent claiming, evidence and playbook matching."""
import threading
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import integration_config
from backend.crud import create_alert, create_containment_action, create_ioc_artifact, create_playbook
from backend.database import Base
from backend.engine import actions as actions_module
from backend.engine import reporter
from backend.engine import runner as runner_module
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS
from backend.engine.runner import (
    AlertBusyError,
    approve_and_contain_alert,
    evaluate_execution_mode,
    match_playbook,
    process_alert,
)
from backend.models import Alert, ContainmentAction, PlaybookExecution

LAB = {"abuseipdb": {"provider": "abuseipdb", "status": "lab_fixture", "threat_score": 95, "verdict": "Malicious"}}
LIVE = {"virustotal": {"provider": "virustotal", "status": "live", "threat_score": 90, "verdict": "Malicious"}}
EXPECTED = ["isolate_endpoint", "terminate_process", "block_ip", "revoke_user_sessions"]


def ransomware(srcip="198.51.100.45", **extra):
    payload = {
        "rule": {"id": "100201", "level": 10, "description": "Ransomware activity: bulk file encryption",
                 "mitre": {"id": ["T1486"]}},
        "agent": {"id": "004", "name": "srv-prod-db01", "ip": "10.0.4.15"},
        "data": {"process": "lockbit3_encryptor.exe", "srcip": srcip, "srcuser": "svc_sqladmin"},
    }
    payload.update(extra)
    return payload


@pytest.fixture
def cfg(monkeypatch):
    values = {"hotl_enabled": "true", "simulation_mode": "true"}
    original = integration_config.get_setting

    def fake(key_name, db=None, default=None):
        if key_name in values:
            return values[key_name]
        if key_name == "protected_hosts":
            return "unrelated-protected-host.example"  # HOTL may only run with protected assets listed
        if key_name == "protected_users":
            return "unrelated-breakglass-user"
        if key_name in ("protected_ips", "siem_manager_url"):
            return ""
        return original(key_name, db=db, default=default)

    monkeypatch.setattr(integration_config, "get_setting", fake)
    monkeypatch.setattr(integration_config, "_system_identity", lambda: (["soar-box"], ["127.0.0.0/8", "10.250.250.250"]))
    integration_config.clear_auto_protect_cache()
    return values


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'ws1.db'}", connect_args={"timeout": 30})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(runner_module, "SessionLocal", Session)
    session = Session()
    for pb in PRECONFIGURED_PLAYBOOKS:
        create_playbook(session, pb)
    yield session
    session.close()


def make_alert(db, payload, tips=LAB, ip="198.51.100.45", severity="High"):
    alert = create_alert(db, {"rule_id": "WAZUH-" + payload["rule"]["id"], "source": "Wazuh SIEM",
                              "severity": severity, "status": "New", "raw_payload": payload})
    if tips is not None:
        create_ioc_artifact(db, alert.alert_id, artifact_type="IP", value=ip, threat_score=95, verdict="Malicious",
                            enrichment_status="enriched", tip_results=tips)
    return alert


def records(db, alert_id):
    db.expire_all()
    return db.query(ContainmentAction).filter(ContainmentAction.alert_id == alert_id).order_by(ContainmentAction.action_id).all()


@pytest.fixture
def live_connectors(monkeypatch):
    """Replace the connector call with a counting live Success (no network)."""
    calls = []

    def fake_dispatch(alert, action, target, params):
        calls.append((alert.alert_id, action, target))
        return {"status": "Success", "execution_mode": "live", "provider": "test", "action": action, "target": target}

    monkeypatch.setattr(actions_module, "_dispatch", fake_dispatch)
    return calls


# --- (a) simulation is not containment --------------------------------------------------

def test_simulated_only_run_is_status_simulated_not_contained(db, cfg):
    alert = make_alert(db, ransomware())
    result = process_alert(alert.alert_id)

    assert result["mode"] == "HOTL"
    assert result["status"] == "Simulated"
    assert result["execution_status"] == "Simulated (HOTL)"
    assert result["mttr_seconds"] is None
    db.expire_all()
    assert db.get(Alert, alert.alert_id).status == "Simulated"
    assert [r.status for r in records(db, alert.alert_id)] == ["Simulated"] * 4


def test_rerun_after_going_live_redoes_simulated_actions_and_contains(db, cfg, request):
    alert = make_alert(db, ransomware())
    assert process_alert(alert.alert_id)["status"] == "Simulated"
    assert [r.status for r in records(db, alert.alert_id)] == ["Simulated"] * 4

    live_connectors = request.getfixturevalue("live_connectors")  # the connectors are now configured
    result = approve_and_contain_alert(db, alert.alert_id, approved_by="lead")

    assert result["status"] == "Contained"
    assert result["already_done"] == []
    assert [c[1] for c in live_connectors] == EXPECTED  # every simulated action was performed for real
    assert result["mttr_seconds"] is not None


def test_live_success_is_skipped_on_rerun(db, cfg, live_connectors):
    alert = make_alert(db, ransomware())
    first = process_alert(alert.alert_id)
    assert first["status"] == "Contained"
    assert [c[1] for c in live_connectors] == EXPECTED

    again = approve_and_contain_alert(db, alert.alert_id, approved_by="lead")
    assert [c[1] for c in live_connectors] == EXPECTED  # nothing executed twice
    assert {d["action"] for d in again["already_done"]} == set(EXPECTED)
    assert again["status"] == "Contained"


def test_one_live_success_among_simulated_actions_is_contained(db, cfg, monkeypatch):
    def mixed(alert, action, target, params):
        if action == "block_ip":
            return {"status": "Success", "execution_mode": "live", "provider": "wazuh"}
        return {"status": "Simulated", "execution_mode": "simulated", "provider": "wazuh"}

    monkeypatch.setattr(actions_module, "_dispatch", mixed)
    alert = make_alert(db, ransomware())
    result = process_alert(alert.alert_id)
    assert result["status"] == "Contained"
    assert result["execution_status"] == "Completed (HOTL, simulated)"


def test_simulated_status_is_not_a_done_status():
    assert "Simulated" not in actions_module.EXECUTED_STATUSES
    assert actions_module.is_live_success("Success", "live")
    assert not actions_module.is_live_success("Success", "simulated")
    assert not actions_module.is_live_success("Simulated", "simulated")


def test_report_states_simulated_is_not_contained(db, cfg, monkeypatch):
    texts = []
    original_build = reporter.SimpleDocTemplate.build

    def capture(self, story, *a, **k):
        for item in story:
            texts.append(getattr(item, "text", ""))
            for row in getattr(item, "_cellvalues", []):
                texts.extend(getattr(cell, "text", "") for cell in row)
        return original_build(self, story, *a, **k)

    monkeypatch.setattr(reporter.SimpleDocTemplate, "build", capture)
    alert = make_alert(db, ransomware())
    result = process_alert(alert.alert_id)
    joined = " ".join(texts)
    assert "NOT CONTAINED" in joined and "SIMULATED" in joined
    assert "are not treated as done" in joined
    assert result["pdf_path"]


# --- (b) idempotency -------------------------------------------------------------------

def test_two_racing_claims_exactly_one_wins(db, cfg):
    alert = make_alert(db, ransomware())
    Session = runner_module.SessionLocal
    s1, s2 = Session(), Session()
    try:
        first = runner_module._claim_alert(s1, alert.alert_id, "New")
        second = runner_module._claim_alert(s2, alert.alert_id, "New")
    finally:
        s1.close()
        s2.close()
    assert first is not None and second is None
    leases = db.query(PlaybookExecution).filter_by(alert_id=alert.alert_id, status="Running").all()
    assert len(leases) == 1


def test_concurrent_process_alert_threads_execute_each_action_once(db, cfg, live_connectors):
    alert = make_alert(db, ransomware())
    results, errors = [], []

    def worker():
        try:
            results.append(process_alert(alert.alert_id))
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert sorted(c[1] for c in live_connectors) == sorted(EXPECTED)
    assert sum(1 for r in results if r.get("mode") == "HOTL") == 1
    assert len(records(db, alert.alert_id)) == 4


def test_reentrant_call_during_a_run_does_nothing(db, cfg, live_connectors, monkeypatch):
    """A redelivery arriving while the first run is mid-flight must not execute anything."""
    alert = make_alert(db, ransomware())
    inner = {}
    original = runner_module.execute_action

    def spy(*args, **kwargs):
        if "result" not in inner:
            inner["result"] = process_alert(alert.alert_id)
        return original(*args, **kwargs)

    monkeypatch.setattr(runner_module, "execute_action", spy)
    outer = process_alert(alert.alert_id)

    assert inner["result"]["status"] == "Processing" and inner["result"]["busy"] is True
    assert outer["status"] == "Contained"
    assert [c[1] for c in live_connectors] == EXPECTED


def test_processing_alert_with_fresh_lease_is_left_alone(db, cfg, live_connectors):
    alert = make_alert(db, ransomware())
    assert runner_module._claim_alert(db, alert.alert_id, "New") is not None
    result = process_alert(alert.alert_id)
    assert result["busy"] is True and live_connectors == []
    with pytest.raises(AlertBusyError):
        approve_and_contain_alert(db, alert.alert_id, approved_by="lead")
    assert records(db, alert.alert_id) == []


def test_stale_claim_is_reclaimed_and_skips_actions_with_a_live_success(db, cfg, live_connectors):
    alert = make_alert(db, ransomware())
    lease_id = runner_module._claim_alert(db, alert.alert_id, "New")
    create_containment_action(db, alert.alert_id, "isolate_endpoint", status="Success", executed_by="HOTL Engine",
                              target="srv-prod-db01", connector="edr", execution_mode="live", details={})
    lease = db.get(PlaybookExecution, lease_id)
    lease.executed_at = lease.executed_at - timedelta(minutes=11)
    db.commit()

    result = process_alert(alert.alert_id)

    assert result["mode"] == "HOTL" and result["status"] == "Contained"
    assert [c[1] for c in live_connectors] == ["terminate_process", "block_ip", "revoke_user_sessions"]
    assert [r.action_type for r in records(db, alert.alert_id)].count("isolate_endpoint") == 1
    db.expire_all()
    finished = db.get(PlaybookExecution, lease_id)
    assert finished.status == "Completed (HOTL)"
    assert db.query(PlaybookExecution).filter_by(alert_id=alert.alert_id).count() == 1


def test_error_during_run_releases_the_claim_for_a_retry(db, cfg, live_connectors, monkeypatch):
    alert = make_alert(db, ransomware())
    with monkeypatch.context() as patch:
        patch.setattr(runner_module, "run_playbook_steps", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        with pytest.raises(RuntimeError):
            process_alert(alert.alert_id)
    db.expire_all()
    assert db.get(Alert, alert.alert_id).status == "New"
    assert [e.status for e in db.query(PlaybookExecution).filter_by(alert_id=alert.alert_id)] == ["Interrupted"]

    assert process_alert(alert.alert_id)["status"] == "Contained"


def test_already_processed_alert_is_not_rerun(db, cfg):
    alert = make_alert(db, ransomware())
    process_alert(alert.alert_id)
    again = process_alert(alert.alert_id)
    assert again["mode"] is None and not again.get("busy")
    assert len(records(db, alert.alert_id)) == 4


# --- (e) evidence -----------------------------------------------------------------------

def test_severity_alone_is_not_evidence_for_any_source(db, cfg):
    for source in ("EDR", "XDR", "Wazuh SIEM"):
        alert = create_alert(db, {"rule_id": "EDR-1", "source": source, "severity": "Critical", "status": "New",
                                  "raw_payload": ransomware()})
        routing = evaluate_execution_mode(db, alert, [], match_playbook(db, alert))
        assert routing["mode"] == "HITL" and routing["evidence"] == []


def test_lab_fixture_is_evidence_only_in_simulation_mode(db, cfg):
    alert = make_alert(db, ransomware(), tips=LAB)
    playbook = match_playbook(db, alert)
    assert evaluate_execution_mode(db, alert, alert.ioc_artifacts, playbook)["mode"] == "HOTL"
    cfg["simulation_mode"] = "false"
    routing = evaluate_execution_mode(db, alert, alert.ioc_artifacts, playbook)
    assert routing["mode"] == "HITL" and routing["evidence"] == []


def test_live_provider_data_is_evidence_with_simulation_off(db, cfg):
    cfg["simulation_mode"] = "false"
    alert = make_alert(db, ransomware(), tips=LIVE)
    routing = evaluate_execution_mode(db, alert, alert.ioc_artifacts, match_playbook(db, alert))
    assert routing["mode"] == "HOTL"
    assert "live threat intelligence" in routing["evidence"][0]


def test_hotl_disabled_by_default_routes_to_hitl(db, cfg):
    cfg.pop("hotl_enabled")
    alert = make_alert(db, ransomware(), tips=LIVE)
    # DEFAULTS decides (no env, no DB row): HOTL is off, so the run is parked for an analyst.
    assert integration_config.DEFAULTS["hotl_enabled"] == "false"
    routing = evaluate_execution_mode(db, alert, alert.ioc_artifacts, match_playbook(db, alert))
    assert routing["mode"] == "HITL" and "switched off" in routing["reasons"][0]


# --- (f) playbook matching vs. injected log text -------------------------------------------

INJECTION = "ransomware lockbit ryuk conti vssadmin shadow copy bulk encryption webshell mimikatz lsass ddos"


def benign(full_log, **rule_extra):
    rule = {"id": "2", "level": 3, "description": "User logged in"}
    rule.update(rule_extra)
    return {"rule": rule, "agent": {"id": "010", "name": "ws-10"}, "full_log": full_log,
            "data": {"srcip": "198.51.100.45"}}


def test_full_log_keywords_alone_never_select_a_hotl_playbook(db, cfg):
    alert = make_alert(db, benign(INJECTION))
    assert match_playbook(db, alert) is None
    result = process_alert(alert.alert_id)
    assert result["mode"] == "HITL" and result["playbook"] is None
    assert records(db, alert.alert_id) == []


def test_full_log_keywords_can_still_suggest_a_hitl_playbook(db, cfg):
    alert = make_alert(db, benign("user clicked a malicious link, possible phishing"))
    assert match_playbook(db, alert).name == "Spearphishing Email & Credential Harvesting"
    assert match_playbook(db, alert).execution_mode == "HITL"


def test_log_injection_cannot_outrank_the_senders_rule(db, cfg):
    payload = {"rule": {"id": "5712", "level": 10, "description": "sshd: brute force trying to get access"},
               "agent": {"id": "010", "name": "ws-10"}, "full_log": INJECTION, "data": {"srcip": "198.51.100.45"}}
    assert match_playbook(db, make_alert(db, payload)).target_threat == "Brute Force"


def test_mitre_id_selects_the_playbook_without_any_keyword(db, cfg):
    payload = {"rule": {"id": "9", "level": 8, "description": "File activity", "mitre": {"id": ["T1486"]}},
               "agent": {"id": "010", "name": "ws-10"}}
    assert match_playbook(db, make_alert(db, payload)).name == "Ransomware Outbreak Containment"


def test_rule_groups_are_a_strong_signal(db, cfg):
    payload = {"rule": {"id": "9", "level": 8, "description": "Alert", "groups": ["web", "webshell"]},
               "agent": {"id": "010", "name": "ws-10"}}
    assert match_playbook(db, make_alert(db, payload)).name == "Web Shell Execution & Backdoor Isolation"


def test_injected_log_cannot_trigger_autonomous_containment_end_to_end(db, cfg, live_connectors):
    alert = make_alert(db, benign(INJECTION), tips=LIVE)
    result = process_alert(alert.alert_id)
    assert result["mode"] == "HITL" and live_connectors == []
