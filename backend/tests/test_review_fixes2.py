"""Regression tests for the second independent review (backend hardening). Every HTTP call is mocked; no real keys."""
import json
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from backend import ratelimit
from backend.crud import create_containment_action, create_ioc_artifact, get_dashboard_metrics
from backend.engine import ai_triage, policy, runner
from backend.models import AgentProposal, Alert, ContainmentAction, SystemLog
from backend.routers import auth as auth_router
from backend.tests.ai_helpers import (  # noqa: F401  (fixtures are used by name)
    FAKE_KEY, _fresh_ai_budget, ai_cfg, all_logs, db, fake_openrouter, new_alert, valid_reply,
)
from backend.tests.test_ai_triage import _service_key, actions_for, approve, autonomous, proposal_row, reject  # noqa: F401
from backend.tests.ws6_helpers import _clean_state, admin_h, bearer, client_from, make_user  # noqa: F401


@pytest.fixture
def analyst_h(client, admin_h):
    make_user(client, admin_h, "rf2_analyst", "SOC Analyst")
    return bearer("rf2_analyst")


@pytest.fixture
def auditor_h(client, admin_h):
    make_user(client, admin_h, "rf2_auditor", "SOC Auditor (Read-Only)")
    return bearer("rf2_auditor")


def propose(client, key, alert_id, **overrides):
    return client.post(f"/api/agent/alerts/{alert_id}/proposals", headers=key, json=valid_reply(**overrides))


# --- 1. reversals of human containment never run unattended for the agent -------------------------------------

@pytest.mark.parametrize("autonomy", ["low_impact", "policy"])
@pytest.mark.parametrize("action,target", [("unisolate_endpoint", "srv-app01"), ("unblock_ip", "198.51.100.45")])
def test_agent_reversals_always_need_approval(db, ai_cfg, autonomy, action, target):
    autonomous(ai_cfg, autonomy)
    alert = new_alert(db)
    decision = policy.evaluate_action(db, alert, action, target, actor="agent", confidence=0.99)
    assert decision.allowed and decision.requires_approval
    assert any("reverses a containment step" in reason for reason in decision.reasons)
    # an ordinary low-impact action is still autonomous at that confidence, so the reversal rule is what holds it back
    assert policy.ACTION_CATALOG[action]["impact"] == "low"
    assert not policy.evaluate_action(db, alert, "send_notification", None, {"message": "x"}, actor="agent",
                                      confidence=0.99).requires_approval
    # humans and playbooks are unaffected by the agent-only rule
    assert not policy.evaluate_action(db, alert, action, target, actor="analyst").requires_approval


def test_agent_reversal_without_the_rule_would_have_run(db, ai_cfg, monkeypatch):
    """Reproduction of the original defect: with the rule removed the same request is autonomous."""
    autonomous(ai_cfg, "low_impact")
    alert = new_alert(db)
    monkeypatch.setattr(policy, "REVERSAL_ACTIONS", set())
    assert not policy.evaluate_action(db, alert, "unblock_ip", "198.51.100.45", actor="agent",
                                      confidence=0.99).requires_approval


def test_agent_api_reversal_waits_for_an_analyst(client, admin_h, db, ai_cfg):
    autonomous(ai_cfg, "policy")
    key = _service_key(client, admin_h, "rf2-reversal-agent")
    alert = new_alert(db)
    body = valid_reply(actions=[{"action": "unblock_ip", "target": "198.51.100.45", "params": {}}])
    res = client.post(f"/api/agent/alerts/{alert.alert_id}/proposals", headers=key, json=body)
    assert res.status_code == 201 and res.json()["status"] == "pending_approval"
    assert actions_for(db, alert.alert_id) == []


# --- 2. agent-key proposals: same busy/unknown checks and a per-key rate limit ----------------------------------

def test_agent_proposal_unknown_alert_404_and_processing_alert_409(client, admin_h, db, ai_cfg):
    key = _service_key(client, admin_h, "rf2-busy-agent")
    assert propose(client, key, 99999999).status_code == 404
    alert = new_alert(db, status=runner.STATUS_PROCESSING)
    res = propose(client, key, alert.alert_id)
    assert res.status_code == 409 and "processed" in res.json()["detail"] and "retry-after" in res.headers
    assert db.query(AgentProposal).filter(AgentProposal.alert_id == alert.alert_id).count() == 0
    db.query(Alert).filter(Alert.alert_id == alert.alert_id).update({Alert.status: "Triaged"})
    db.commit()
    assert propose(client, key, alert.alert_id).status_code == 201


def test_agent_proposal_conflicts_while_the_alert_is_being_triaged(client, admin_h, db, ai_cfg):
    key = _service_key(client, admin_h, "rf2-inflight-agent")
    alert = new_alert(db)
    assert ai_triage._claim_inflight(alert.alert_id)
    try:
        res = propose(client, key, alert.alert_id)
        assert res.status_code == 409 and "already being triaged" in res.json()["detail"]
    finally:
        ai_triage._release_inflight(alert.alert_id)
    assert propose(client, key, alert.alert_id).status_code == 201
    assert alert.alert_id not in ai_triage._inflight  # the claim is always released


def test_agent_proposal_rate_limit_is_per_key_and_env_tunable(client, admin_h, db, ai_cfg, monkeypatch):
    assert ratelimit.get_limit("agent_proposals") == (30, 60)
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_AGENT_PROPOSALS", "2/60")
    first = _service_key(client, admin_h, "rf2-rate-a")
    second = _service_key(client, admin_h, "rf2-rate-b")
    alert = new_alert(db)
    assert propose(client, first, alert.alert_id).status_code == 201
    assert propose(client, first, alert.alert_id).status_code == 201
    limited = propose(client, first, alert.alert_id)
    assert limited.status_code == 429 and "retry-after" in limited.headers
    assert db.query(AgentProposal).filter(AgentProposal.alert_id == alert.alert_id).count() == 2
    assert propose(client, second, alert.alert_id).status_code == 201   # another key has its own budget
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_AGENT_PROPOSALS", "off")
    assert propose(client, first, alert.alert_id).status_code == 201


def _model_calls(db):
    db.expire_all()
    return db.query(SystemLog).filter(SystemLog.source == "AI", SystemLog.message.like(f"{ai_triage.CALL_MARKER}%")).count()


def test_reserve_model_call_counts_in_one_process_and_gives_a_refused_slot_back(db, ai_cfg):
    ai_cfg["ai_max_alerts_per_minute"] = "2"
    ai_triage._reserve_model_call(db, 1, "manual", "m")
    ai_triage._reserve_model_call(db, 1, "manual", "m")
    with pytest.raises(ai_triage.AIRateLimited) as info:
        ai_triage._reserve_model_call(db, 1, "manual", "m")
    assert info.value.retry_after >= 1.0
    assert _model_calls(db) == 2          # the refused reservation did not keep its row


def test_reserve_model_call_is_insert_then_count(db, ai_cfg, monkeypatch):
    """A concurrent process that inserts between our read and our write must not let us exceed the budget: our
    row is written first and ranked against everything already there."""
    from backend.routers import logs

    ai_cfg["ai_max_alerts_per_minute"] = "1"
    real = logs.record_log
    other = {"done": False}

    def racing_record_log(*args, **kwargs):
        if not other["done"]:               # the "other worker" gets in just before our insert
            other["done"] = True
            real(args[0], "AI", "INFO", f"{ai_triage.CALL_MARKER} for Alert #9 (auto, model m).", "Alert #9", {})
        return real(*args, **kwargs)

    monkeypatch.setattr(logs, "record_log", racing_record_log)
    with pytest.raises(ai_triage.AIRateLimited):
        ai_triage._reserve_model_call(db, 1, "manual", "m")
    assert _model_calls(db) == 1


def test_reserve_model_call_threads_never_exceed_the_limit(db, ai_cfg):
    from backend.database import SessionLocal

    ai_cfg["ai_max_alerts_per_minute"] = "3"
    outcomes = []

    def worker():
        session = SessionLocal()
        try:
            ai_triage._reserve_model_call(session, 1, "manual", "m")
            outcomes.append("ok")
        except ai_triage.AIRateLimited:
            outcomes.append("limited")
        finally:
            session.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 3 and outcomes.count("limited") == 5
    assert _model_calls(db) == 3


# --- 3. approval interrupted between the claim and the actions: recoverable -----------------------------------

def _pending_proposal(client, admin_h, db, name):
    key = _service_key(client, admin_h, name)
    alert = new_alert(db)
    res = propose(client, key, alert.alert_id)
    assert res.status_code == 201 and res.json()["status"] == "pending_approval"
    return alert, res.json()["proposal_id"]


def test_approval_that_raises_can_be_retried(client, admin_h, analyst_h, db, ai_cfg, monkeypatch):
    alert, pid = _pending_proposal(client, admin_h, db, "rf2-approve-crash")
    real_get_alert = ai_triage.get_alert
    calls = {"n": 0}

    def exploding_get_alert(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database went away")
        return real_get_alert(*args, **kwargs)

    monkeypatch.setattr(ai_triage, "get_alert", exploding_get_alert)
    with pytest.raises(RuntimeError):
        ai_triage.approve_proposal(db, pid, "rf2_analyst")
    row = proposal_row(db, pid)
    assert row.status == "approved" and not (row.execution_results or [])      # claimed, nothing ran
    assert ai_triage.approval_incomplete(row) and actions_for(db, alert.alert_id) == []
    assert reject(client, analyst_h, pid).status_code == 409                    # still no way to un-decide it

    retry = approve(client, analyst_h, pid)                                     # POST approve again: resumes
    assert retry.status_code == 200, retry.text
    assert retry.json()["proposal"]["status"] == "approved"
    (result,) = retry.json()["results"]
    assert result["executed_by"] == "rf2_analyst" and result["status"] == "Simulated"
    assert len(actions_for(db, alert.alert_id)) == 1
    assert not ai_triage.approval_incomplete(proposal_row(db, pid))
    assert approve(client, analyst_h, pid).status_code == 409                   # finished: a further approve conflicts
    assert len(actions_for(db, alert.alert_id)) == 1


def test_crashed_approval_is_resumable_only_after_its_lease(client, admin_h, analyst_h, db, ai_cfg):
    """A process that dies leaves no chance to hand the lease back: the retry waits for the lease to run out, so a
    slow but alive first attempt is never run twice at the same time."""
    alert, pid = _pending_proposal(client, admin_h, db, "rf2-approve-lease")
    db.query(AgentProposal).filter(AgentProposal.proposal_id == pid).update(
        {AgentProposal.status: "approved", AgentProposal.decided_by: "ghost", AgentProposal.decided_at: datetime.now(timezone.utc)})
    db.commit()
    blocked = approve(client, analyst_h, pid)
    assert blocked.status_code == 409 and "retry-after" in blocked.headers
    assert actions_for(db, alert.alert_id) == []

    old = datetime.now(timezone.utc) - timedelta(seconds=ai_triage.APPROVAL_LEASE_SECONDS + 5)
    db.query(AgentProposal).filter(AgentProposal.proposal_id == pid).update({AgentProposal.decided_at: old})
    db.commit()
    resumed = approve(client, analyst_h, pid, notes="resuming after the crash")
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["proposal"]["decided_by"] == "rf2_analyst"
    assert len(actions_for(db, alert.alert_id)) == 1
    assert approve(client, analyst_h, pid).status_code == 409


def test_resume_claim_is_compare_and_swap(client, admin_h, db, ai_cfg):
    alert, pid = _pending_proposal(client, admin_h, db, "rf2-approve-cas")
    old = datetime.now(timezone.utc) - timedelta(seconds=ai_triage.APPROVAL_LEASE_SECONDS + 5)
    db.query(AgentProposal).filter(AgentProposal.proposal_id == pid).update(
        {AgentProposal.status: "approved", AgentProposal.decided_at: old})
    db.commit()
    assert ai_triage._claim_resume(db, pid, "first", None).decided_by == "first"
    with pytest.raises(ai_triage.ProposalConflict):                    # the second contender loses
        ai_triage._claim_resume(db, pid, "second", None)
    assert proposal_row(db, pid).decided_by == "first"


def test_complete_approval_is_not_resumable_and_other_statuses_conflict(client, admin_h, analyst_h, db, ai_cfg):
    _alert, pid = _pending_proposal(client, admin_h, db, "rf2-approve-final")
    assert approve(client, analyst_h, pid).status_code == 200
    assert approve(client, analyst_h, pid).status_code == 409
    _alert2, other = _pending_proposal(client, admin_h, db, "rf2-approve-rejected")
    assert reject(client, analyst_h, other).status_code == 200
    assert approve(client, analyst_h, other).status_code == 409


# --- 4. service-account keys expire by default ---------------------------------------------------------------------

def _create_service(client, admin_h, name, **body):
    for user in client.get("/api/users", headers=admin_h).json():
        if user["username"] == name:
            client.delete(f"/api/users/{user['user_id']}", headers=admin_h)
    res = client.post("/api/users/service-accounts", headers=admin_h, json={"username": name, **body})
    assert res.status_code == 201, res.text
    return res.json()


def _days_left(created):
    expires = datetime.fromisoformat(created["expires_at"])
    expires = expires if expires.tzinfo else expires.replace(tzinfo=timezone.utc)
    return (expires - datetime.now(timezone.utc)).total_seconds() / 86400


def test_service_key_defaults_to_90_days(client, admin_h, monkeypatch):
    monkeypatch.delenv("PHANTOM_AGENT_KEY_DEFAULT_DAYS", raising=False)
    assert 89.9 < _days_left(_create_service(client, admin_h, "rf2-key-default")) < 90.1


def test_service_key_default_is_configurable_and_zero_means_none(client, admin_h, monkeypatch):
    monkeypatch.setenv("PHANTOM_AGENT_KEY_DEFAULT_DAYS", "30")
    assert 29.9 < _days_left(_create_service(client, admin_h, "rf2-key-30")) < 30.1
    monkeypatch.setenv("PHANTOM_AGENT_KEY_DEFAULT_DAYS", "0")
    assert _create_service(client, admin_h, "rf2-key-none")["expires_at"] is None
    monkeypatch.setenv("PHANTOM_AGENT_KEY_DEFAULT_DAYS", "not-a-number")
    assert 89.9 < _days_left(_create_service(client, admin_h, "rf2-key-bad-env")) < 90.1


def test_explicit_expiry_still_wins(client, admin_h, monkeypatch):
    monkeypatch.setenv("PHANTOM_AGENT_KEY_DEFAULT_DAYS", "0")
    assert 6.9 < _days_left(_create_service(client, admin_h, "rf2-key-explicit", expires_in_days=7)) < 7.1
    monkeypatch.setenv("PHANTOM_AGENT_KEY_DEFAULT_DAYS", "90")
    assert 6.9 < _days_left(_create_service(client, admin_h, "rf2-key-explicit2", expires_in_days=7)) < 7.1
    listed = {u["username"]: u for u in client.get("/api/users", headers=admin_h).json()}
    assert listed["rf2-key-explicit2"]["expires_at"]


# --- 5. logs and read-only masking ---------------------------------------------------------------------------------

def test_failed_login_for_unknown_user_does_not_log_the_typed_text(client, db, caplog):
    typed = "Tr0ub4dor&3-my-real-password"
    with caplog.at_level("DEBUG"):
        res = client.post("/api/auth/login", json={"username": typed, "password": "whatever-else-1"})
    assert res.status_code == 401
    db.expire_all()
    entries = [r for r in db.query(SystemLog).filter(SystemLog.source == "AUTH").all() if "Failed sign-in" in r.message]
    assert entries
    for entry in entries[-1:]:
        blob = json.dumps(entry.to_dict())
        assert typed not in blob and "Tr0ub4dor" not in blob
        assert "unknown user #" in entry.message and f"{len(typed)} chars" in entry.message
    assert typed not in caplog.text
    # the same typed text always hashes to the same short label, so repeated attempts can be correlated
    assert auth_router._unknown_label(typed) == auth_router._unknown_label(typed) != auth_router._unknown_label(typed + "x")


def test_failed_login_for_an_existing_user_keeps_the_name(client, admin_h, db):
    make_user(client, admin_h, "rf2_known_user")
    res = client.post("/api/auth/login", json={"username": "rf2_known_user", "password": "definitely-wrong-1"})
    assert res.status_code == 401
    db.expire_all()
    last = [r for r in db.query(SystemLog).filter(SystemLog.source == "AUTH").order_by(SystemLog.log_id).all()
            if "Failed sign-in" in r.message][-1]
    assert "'rf2_known_user'" in last.message and last.target == "rf2_known_user"


def _alert_with_sensitive_content(db):
    alert = new_alert(db)
    create_ioc_artifact(db, alert.alert_id, "Email", "bob.attacker@evil.example", 40, verdict="Suspicious")
    proposal = AgentProposal(
        alert_id=alert.alert_id, agent_name="rf2-agent", verdict="malicious", confidence=0.9,
        summary="Contact carol.admin@corp.example, token=abcd1234efgh5678 was seen",
        reasoning="password=hunter2-SECRET used by dave@corp.example",
        proposed_actions=[{"action": "disable_account", "target": "carol.admin@corp.example", "params": {}}],
        policy_evaluation=[{"action": "disable_account", "target": "carol.admin@corp.example", "allowed": True,
                            "requires_approval": True, "reasons": ["api_key=zzzz9999yyyy8888 in the log"]}],
        execution_results=[], status="pending_approval")
    db.add(proposal)
    db.commit()
    db.refresh(proposal)
    return alert, proposal


def _shape(value):
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shape(v) for v in value[:1]]
    return type(value).__name__


def test_auditor_sees_masked_iocs_entities_and_proposals_with_the_same_shape(client, auditor_h, analyst_h, db, ai_cfg):
    alert, proposal = _alert_with_sensitive_content(db)
    leaks = ("bob.attacker@", "carol.admin@", "dave@", "jdoe@", "hunter2", "abcd1234efgh5678", "zzzz9999yyyy8888")

    plain = client.get(f"/api/alerts/{alert.alert_id}", headers=analyst_h).json()
    masked = client.get(f"/api/alerts/{alert.alert_id}", headers=auditor_h).json()
    text = json.dumps(masked)
    for leaked in leaks:
        assert leaked not in text, leaked
    assert "b***@evil.example" in text and "c***@corp.example" in text
    assert "carol.admin@corp.example" in json.dumps(plain)               # operators still see the real values
    assert _shape(masked) == _shape(plain)                                # same field names and types
    assert {i["value"] for i in masked["ioc_artifacts"]} >= {"198.51.100.45", "b***@evil.example"}
    assert masked["entities"]["ips"] == plain["entities"]["ips"] and "198.51.100.45" in masked["entities"]["ips"]

    listed = client.get("/api/agent/proposals", headers=auditor_h, params={"alert_id": alert.alert_id}).json()["items"]
    single = client.get(f"/api/agent/proposals/{proposal.proposal_id}", headers=auditor_h).json()
    plain_single = client.get(f"/api/agent/proposals/{proposal.proposal_id}", headers=analyst_h).json()
    for blob in (json.dumps(listed), json.dumps(single)):
        for leaked in leaks:
            assert leaked not in blob, leaked
    assert _shape(single) == _shape(plain_single) and "carol.admin@corp.example" in json.dumps(plain_single)
    assert single["proposed_actions"][0]["action"] == "disable_account"

    rows = client.get("/api/alerts", headers=auditor_h, params={"limit": 200}).json()
    assert next(r for r in rows if r["alert_id"] == alert.alert_id)["raw_payload"]["data"]["srcuser"] == "j***@corp.example"


# --- 6. bootstrap name, dashboard metric ---------------------------------------------------------------------------

def test_bootstrap_name_never_returns_a_rejected_value(monkeypatch):
    monkeypatch.setattr(auth_router, "_bootstrap_username", "abunemah")
    for rejected in ("has space", "ab", "-leading-dash", "x" * 80, "semi;colon"):
        monkeypatch.setenv("PHANTOM_BOOTSTRAP_ADMIN_USERNAME", rejected)
        assert auth_router.get_bootstrap_admin_username() == "abunemah", rejected
    monkeypatch.setattr(auth_router, "_bootstrap_username", None)
    monkeypatch.setenv("PHANTOM_BOOTSTRAP_ADMIN_USERNAME", "has space")
    assert auth_router.get_bootstrap_admin_username() == auth_router.DEFAULT_BOOTSTRAP_ADMIN_USERNAME
    monkeypatch.setenv("PHANTOM_BOOTSTRAP_ADMIN_USERNAME", "soc-admin")      # a valid one is honoured
    assert auth_router.get_bootstrap_admin_username() == "soc-admin"


def test_automated_actions_metric_excludes_analyst_runs(client, admin_h, db):
    make_user(client, admin_h, "rf2_metric_analyst")
    svc = _create_service(client, admin_h, "rf2-metric-agent")["username"]
    alert = new_alert(db)
    before = get_dashboard_metrics(db)
    for who, mode in (("rf2_metric_analyst", "live"), ("rf2_metric_analyst", "simulated"), ("abunemah", "simulated"),
                      (runner.HOTL_ENGINE, "simulated"), (runner.HOTL_ENGINE, "live"), (svc, "simulated"),
                      ("phantom-ai", "simulated"), (runner.HOTL_ENGINE, "blocked")):
        create_containment_action(db, alert.alert_id, "block_ip", status="Executed", executed_by=who,
                                  target="198.51.100.45", connector="firewall", execution_mode=mode)
    after = get_dashboard_metrics(db)
    assert after["automated_actions"] - before["automated_actions"] == 4      # engine x2, service account, built-in AI
    assert after["live_actions"] - before["live_actions"] == 2                # per-mode counts still cover every run
    assert after["simulated_actions"] - before["simulated_actions"] == 5
    assert after["blocked_actions"] - before["blocked_actions"] == 1


# --- 7. unattended IP targets ----------------------------------------------------------------------------------------

def test_step_targets_unattended_only_malicious_ips_approved_keeps_non_clean():
    alert = SimpleNamespace(alert_id=1, raw_payload={"agent": {"id": "001", "name": "ws-1", "ip": "10.0.0.5"}})
    ioc = lambda value, verdict: SimpleNamespace(artifact_type="IP", value=value, verdict=verdict)  # noqa: E731
    iocs = [ioc("198.51.100.1", "Malicious"), ioc("198.51.100.2", "Suspicious"), ioc("198.51.100.3", "Unknown"),
            ioc("198.51.100.4", "Clean")]
    entities = {"ips": ["10.0.0.5", "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "203.0.113.9"]}
    assert runner._step_targets("block_ip", alert, iocs, entities, approved=False) == ["198.51.100.1"]
    assert runner._step_targets("block_ip", alert, iocs, entities) == ["198.51.100.1"]          # unattended is the default
    approved = runner._step_targets("block_ip", alert, iocs, entities, approved=True)
    assert approved == ["198.51.100.1", "198.51.100.2", "198.51.100.3", "203.0.113.9"]          # never clean, never the host
    assert runner._step_targets("block_ip", alert, [], entities, approved=False) == []
