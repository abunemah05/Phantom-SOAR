"""Who may change whom (backend/rbac.py + backend/routers/users.py; docs/ACCESS_CONTROL.md).

Covers: self-escalation / self-lockout, bootstrap and last-administrator protection (including a real race),
service accounts (never administrators, never able to manage accounts), the step-up for sensitive changes to other
administrators, role validation, mass-assignment protection and the audit trail of accepted and rejected changes.
"""
import threading
import time
from contextlib import contextmanager

import pyotp
import pytest

from backend import rbac, ratelimit
from backend.rbac import Action, Subject, decide, decide_update
from backend.tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from backend.tests.ws6_helpers import _clean_state, admin_h, bearer, client_from, make_request  # noqa: F401

STRONG = "Correct-Horse-Battery-Staple-26"
CREATED = []  # usernames created by these tests, removed at the end of each test


def _confirm(password=ADMIN_PASSWORD, mfa_code=None):
    body = {"current_password": password}
    if mfa_code:
        body["mfa_code"] = mfa_code
    return {"confirmation": body}


def _db():
    from backend.database import SessionLocal
    return SessionLocal()


def _delete_directly(*names):
    from backend.models import User
    from backend.security_models import ServiceAccountPolicy
    db = _db()
    try:
        for user in db.query(User).filter(User.username.in_(names)).all():
            db.query(ServiceAccountPolicy).filter(ServiceAccountPolicy.user_id == user.user_id).delete(synchronize_session=False)
            db.delete(user)
        db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    _delete_directly(*CREATED)
    CREATED.clear()


def provision(client, admin_h, username, role="SOC Analyst", password=STRONG):
    """Create an account through the admin API and finish the first-login password change."""
    _delete_directly(username)
    CREATED.append(username)
    # Creating an Admin needs the acting admin's step-up confirmation (the bootstrap admin's own password).
    created = client.post("/api/users", json={"username": username, "role": role, **_confirm()}, headers=admin_h)
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={"username": username, "password": created.json()["temporary_password"]})
    assert login.status_code == 200, login.text
    change = client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {login.json()['access_token']}"},
                         json={"current_password": created.json()["temporary_password"], "new_password": password})
    assert change.status_code == 200, change.text
    return {"user_id": created.json()["user_id"], "username": username, "password": password,
            "headers": {"Authorization": f"Bearer {change.json()['access_token']}"}}


def service_account(client, admin_h, name):
    _delete_directly(name)
    CREATED.append(name)
    res = client.post("/api/users/service-accounts", json={"username": name}, headers=admin_h)
    assert res.status_code == 201, res.text
    return res.json()


def me(client, admin_h):
    return next(u for u in client.get("/api/users", headers=admin_h).json() if u["username"] == ADMIN_USERNAME)


def code_of(res):
    return res.json()["detail"]["code"]


def rbac_logs(**details):
    from backend.models import SystemLog
    db = _db()
    try:
        rows = db.query(SystemLog).filter(SystemLog.source == "RBAC").order_by(SystemLog.log_id).all()
        return [r for r in rows if all((r.details or {}).get(k) == v for k, v in details.items())]
    finally:
        db.close()


def stored(username):
    from backend.models import User
    db = _db()
    try:
        u = db.query(User).filter(User.username == username).first()
        return None if u is None else {"role": u.role, "is_active": u.is_active, "is_service_account": u.is_service_account,
                                       "password_hash": u.password_hash, "must_change_password": u.must_change_password,
                                       "compromised": u.compromised_reset_required}
    finally:
        db.close()


@contextmanager
def only_admins(*usernames):
    """Make exactly these human accounts the active administrators, then restore everything."""
    from backend.models import User
    db = _db()
    try:
        saved = {u.user_id: (u.role, u.is_active) for u in db.query(User).all()}
        for u in db.query(User).filter(User.is_service_account.is_(False)).all():
            if u.username in usernames:
                u.role, u.is_active = "Admin", True
            elif rbac.role_level(u.role) == "admin":
                u.is_active = False
        db.commit()
    finally:
        db.close()
    try:
        yield
    finally:
        db = _db()
        try:
            for u in db.query(User).all():
                if u.user_id in saved:
                    u.role, u.is_active = saved[u.user_id]
            db.commit()
        finally:
            db.close()


# =====================================================================================================================
# Pure policy (backend/rbac.py)
# =====================================================================================================================
ADMIN = Subject(1, "root", "Admin")
OTHER_ADMIN = Subject(2, "root2", "Admin")
ANALYST = Subject(3, "ana", "SOC Analyst")
BOOT = Subject(4, "boot", "Admin", is_bootstrap=True)
AGENT = Subject(5, "agent", "AI Agent", is_service_account=True)


@pytest.mark.parametrize("action,target,kwargs,allowed,code,step_up", [
    # self: no escalation, no lock-out
    (Action.CHANGE_ROLE, ADMIN, {"new_role": "SOC Analyst"}, False, "self_role_change", False),
    (Action.CHANGE_ROLE, ADMIN, {"new_role": "Admin"}, True, "ok", False),  # no change at all
    (Action.SET_ACTIVE, ADMIN, {"new_is_active": False}, False, "self_disable", False),
    (Action.DELETE, ADMIN, {}, False, "self_delete", False),
    (Action.RESET_PASSWORD, ADMIN, {}, False, "self_password_reset", False),
    (Action.SET_COMPROMISED, ADMIN, {"new_compromised": True}, False, "self_compromised_flag", False),
    # people who are not administrators: no step-up, except granting Admin
    (Action.CHANGE_ROLE, ANALYST, {"new_role": "Security Engineer"}, True, "ok", False),
    (Action.CHANGE_ROLE, ANALYST, {"new_role": "Admin"}, True, "ok", True),
    (Action.SET_ACTIVE, ANALYST, {"new_is_active": False}, True, "ok", False),
    (Action.RESET_PASSWORD, ANALYST, {}, True, "ok", False),
    (Action.DELETE, ANALYST, {}, True, "ok", False),
    (Action.SET_COMPROMISED, ANALYST, {"new_compromised": True}, True, "ok", False),
    # another administrator: step-up for every sensitive change
    (Action.CHANGE_ROLE, OTHER_ADMIN, {"new_role": "SOC Analyst"}, True, "ok", True),
    (Action.SET_ACTIVE, OTHER_ADMIN, {"new_is_active": False}, True, "ok", True),
    (Action.RESET_PASSWORD, OTHER_ADMIN, {}, True, "ok", True),
    (Action.SET_COMPROMISED, OTHER_ADMIN, {"new_compromised": True}, True, "ok", True),
    (Action.UNLOCK, OTHER_ADMIN, {}, True, "ok", False),
    # the bootstrap administrator is always an active administrator
    (Action.CHANGE_ROLE, BOOT, {"new_role": "SOC Analyst"}, False, "bootstrap_protected", False),
    (Action.SET_ACTIVE, BOOT, {"new_is_active": False}, False, "bootstrap_protected", False),
    (Action.DELETE, BOOT, {}, False, "bootstrap_protected", False),
    # service accounts: fixed role, no password, never promoted
    (Action.CHANGE_ROLE, AGENT, {"new_role": "Admin"}, False, "service_account_role_fixed", False),
    (Action.CHANGE_ROLE, AGENT, {"new_role": "SOC Analyst"}, False, "service_account_role_fixed", False),
    (Action.RESET_PASSWORD, AGENT, {}, False, "service_account_no_password", False),
    (Action.UNLOCK, AGENT, {}, False, "service_account_no_password", False),
    (Action.SET_COMPROMISED, AGENT, {"new_compromised": True}, False, "service_account_no_password", False),
    (Action.SET_ACTIVE, AGENT, {"new_is_active": False}, True, "ok", False),
    (Action.DELETE, AGENT, {}, True, "ok", False),
    (Action.ROTATE_KEY, AGENT, {}, True, "ok", False),
    (Action.SERVICE_POLICY, AGENT, {}, True, "ok", False),
    # key actions never apply to people
    (Action.ROTATE_KEY, ANALYST, {}, False, "not_a_service_account", False),
    (Action.SERVICE_POLICY, OTHER_ADMIN, {}, False, "not_a_service_account", False),
    # the human role "AI Agent" can never be assigned
    (Action.CHANGE_ROLE, ANALYST, {"new_role": "AI Agent"}, False, "service_role_not_assignable", False),
])
def test_policy_matrix(action, target, kwargs, allowed, code, step_up):
    d = decide(action, ADMIN, target, **kwargs)
    assert (d.allowed, d.code, d.step_up) == (allowed, code, step_up), d


def test_last_active_administrator_cannot_be_demoted_disabled_or_deleted():
    last = Subject(9, "only", "Admin")
    for action, kw in ((Action.CHANGE_ROLE, {"new_role": "SOC Analyst"}), (Action.SET_ACTIVE, {"new_is_active": False}), (Action.DELETE, {})):
        d = decide(action, ADMIN, last, other_active_admins=0, **kw)
        assert not d.allowed and d.code == "last_admin", (action, d)
        assert decide(action, ADMIN, last, other_active_admins=1, **kw).allowed  # not the last one: fine
    # an inactive admin or a person who is not an admin is not "the last administrator"
    assert decide(Action.DELETE, ADMIN, Subject(9, "x", "Admin", is_active=False), other_active_admins=0).allowed
    assert decide(Action.DELETE, ADMIN, ANALYST, other_active_admins=0).allowed


@pytest.mark.parametrize("actor", [
    AGENT,
    Subject(6, "agent-admin", "Admin", is_service_account=True),  # a corrupted row: service flag with an admin role
    Subject(7, "ana", "SOC Analyst"),
    Subject(8, "off", "Admin", is_active=False),
    Subject(10, "aud", "SOC Auditor (Read-Only)"),
])
def test_only_active_human_administrators_may_manage_accounts(actor):
    for action in Action:
        d = decide(action, actor, ANALYST, new_role="SOC Analyst", new_is_active=False, new_compromised=True)
        assert not d.allowed and d.code in ("service_account_cannot_manage", "actor_not_admin"), (action, d)
    assert not decide_update(actor, ANALYST, new_role="Admin").allowed


def test_update_is_all_or_nothing_and_step_up_is_merged():
    d = decide_update(ADMIN, ANALYST, new_role="Security Engineer", new_is_active=False)
    assert d.allowed and not d.step_up
    d = decide_update(ADMIN, ANALYST, new_role="Admin", new_is_active=False)
    assert d.allowed and d.step_up
    d = decide_update(ADMIN, BOOT, new_role="Admin", new_is_active=False)  # one refused field refuses the request
    assert not d.allowed and d.code == "bootstrap_protected"
    assert decide_update(ADMIN, ANALYST).allowed


def test_creating_an_administrator_is_a_sensitive_grant_that_needs_step_up(monkeypatch):
    assert rbac.STEP_UP_ON_ADMIN_CREATE is True and rbac.STEP_UP_ON_ADMIN_DELETE is True  # on by default
    assert decide(Action.CREATE_USER, ADMIN, new_role="Admin").step_up is True
    assert decide(Action.CREATE_USER, ADMIN, new_role="SOC Analyst").step_up is False
    monkeypatch.setattr(rbac, "STEP_UP_ON_ADMIN_DELETE", True)
    assert decide(Action.DELETE, ADMIN, OTHER_ADMIN, other_active_admins=2).step_up is True
    assert decide(Action.DELETE, ADMIN, ANALYST).step_up is False


@pytest.mark.parametrize("raw,expected", [
    ("Admin", "Admin"), ("admin", "Admin"), ("  ADMIN ", "Admin"), ("security   engineer", "Security Engineer"),
    ("SOC Analyst", "SOC Analyst"), ("soc auditor (read-only)", "SOC Auditor (Read-Only)"),
    ("Tier 2 Analyst (Senior Responder)", "Tier 2 Analyst (Senior Responder)"),  # legacy non-admin names still work
])
def test_assignable_roles_are_canonicalised(raw, expected):
    assert rbac.validate_assignable_role(raw) == expected


@pytest.mark.parametrize("raw,code", [
    ("", "role_required"), ("   ", "role_required"), (None, "role_required"),
    ("Supreme Overlord", "unknown_role"), ("Admin; DROP TABLE users", "unknown_role"), ("Administrator ", "legacy_admin_alias"),
    ("Sys Admin", "legacy_admin_alias"), ("SOC Lead / Admin", "legacy_admin_alias"),
    ("AI Agent", "service_role_not_assignable"), ("service account", "service_role_not_assignable"),
    ("Adm1n", "unknown_role"), ("Admin Admin", "unknown_role"), ("Admin​", "unknown_role"),
])
def test_invented_service_and_legacy_admin_roles_are_refused(raw, code):
    with pytest.raises(rbac.PolicyViolation) as err:
        rbac.validate_assignable_role(raw)
    assert err.value.code == code


def test_unknown_fields_helper_whitelists():
    assert rbac.unknown_fields({"role": 1, "is_service_account": True, "username": "x"}, rbac.UPDATABLE_FIELDS) == ["is_service_account", "username"]
    assert rbac.unknown_fields(None) == [] and rbac.unknown_fields({}) == []
    assert "is_service_account" not in rbac.UPDATABLE_FIELDS | rbac.CREATABLE_FIELDS | rbac.SERVICE_CREATABLE_FIELDS
    assert "role" not in rbac.SERVICE_CREATABLE_FIELDS  # a service account's role cannot be chosen at creation either


# =====================================================================================================================
# (a) Self-escalation and self-lockout through the API
# =====================================================================================================================
def test_an_admin_cannot_change_their_own_role_or_disable_or_delete_or_reset_themselves(client, admin_h):
    admin2 = provision(client, admin_h, "ac_self", role="Admin")
    uid = admin2["user_id"]
    for body in ({"role": "SOC Analyst"}, {"role": "Security Engineer"}, {"is_active": False}, {"compromised_reset_required": True}):
        res = client.put(f"/api/users/{uid}", json=body, headers=admin2["headers"])
        assert res.status_code == 400, (body, res.text)
        assert code_of(res) in ("self_role_change", "self_disable", "self_compromised_flag")
    assert client.delete(f"/api/users/{uid}", headers=admin2["headers"]).status_code == 400
    assert code_of(client.post(f"/api/users/{uid}/reset-password", headers=admin2["headers"])) == "self_password_reset"
    assert code_of(client.post(f"/api/users/{uid}/flag-compromised", headers=admin2["headers"])) == "self_compromised_flag"
    assert stored("ac_self")["role"] == "Admin" and stored("ac_self")["is_active"] is True
    # Even a correct confirmation does not unlock a self change.
    res = client.put(f"/api/users/{uid}", json={"role": "SOC Analyst", **_confirm(admin2["password"])}, headers=admin2["headers"])
    assert res.status_code == 400 and stored("ac_self")["role"] == "Admin"
    # Sending the role you already have changes nothing and is harmless.
    assert client.put(f"/api/users/{uid}", json={"role": "Admin"}, headers=admin2["headers"]).status_code == 200


def test_a_non_admin_cannot_promote_themselves(client, admin_h):
    analyst = provision(client, admin_h, "ac_climber", role="SOC Analyst")
    for role in ("Admin", "admin", "Sys Admin", "Security Engineer"):
        res = client.put(f"/api/users/{analyst['user_id']}", json={"role": role}, headers=analyst["headers"])
        assert res.status_code == 403, res.text
    assert client.post("/api/users", json={"username": "ac_minion", "role": "Admin"}, headers=analyst["headers"]).status_code == 403
    assert stored("ac_climber")["role"] == "SOC Analyst" and stored("ac_minion") is None


# =====================================================================================================================
# (b) Bootstrap and last administrator
# =====================================================================================================================
def test_bootstrap_admin_cannot_be_demoted_disabled_or_deleted_even_by_another_admin(client, admin_h):
    admin2 = provision(client, admin_h, "ac_second", role="Admin")
    boot = me(client, admin_h)
    for body, code in (({"role": "SOC Analyst"}, "bootstrap_protected"), ({"is_active": False}, "bootstrap_protected")):
        res = client.put(f"/api/users/{boot['user_id']}", json={**body, **_confirm(admin2["password"])}, headers=admin2["headers"])
        assert res.status_code == 400 and code_of(res) == code, res.text
    assert client.delete(f"/api/users/{boot['user_id']}", headers=admin2["headers"]).status_code == 400
    assert stored(ADMIN_USERNAME)["role"] == boot["role"] and stored(ADMIN_USERNAME)["is_active"] is True


def test_the_acting_admin_is_re_checked_under_the_lock(client, admin_h):
    """An administrator whose rights were removed a moment ago cannot complete a change started with a stale view."""
    from backend.models import User
    from backend.routers import users as users_router
    from fastapi import HTTPException

    victim = provision(client, admin_h, "ac_stale", role="Admin")
    db = _db()
    try:
        stale = db.query(User).filter(User.username == "ac_stale").first()
        other = _db()
        try:
            other.query(User).filter(User.username == "ac_stale").update({"role": "SOC Analyst"})
            other.commit()
        finally:
            other.close()
        with pytest.raises(HTTPException) as err:
            with users_router._account_change(db, stale, make_request("127.0.0.1"), "update account", victim["user_id"]):
                raise AssertionError("must not get here")  # pragma: no cover
        assert err.value.status_code == 403 and err.value.detail["code"] == "admin_rights_revoked"
    finally:
        db.close()
    assert rbac_logs(code="admin_rights_revoked", by="ac_stale")


def test_two_admins_demoting_each_other_at_the_same_time_never_leave_zero_admins(client, admin_h, monkeypatch):
    """The classic race: A demotes B while B demotes A. Both would see 'another admin exists'. Exactly one may win."""
    import backend.routers.users as users_router

    other = provision(client, admin_h, "ac_racer", role="Admin")
    monkeypatch.setattr(users_router, "get_bootstrap_admin_username", lambda: "nobody-is-bootstrap")
    boot_id = me(client, admin_h)["user_id"]
    boot_headers = bearer(ADMIN_USERNAME)
    clients = [client_from("198.51.100.10"), client_from("198.51.100.11")]
    outcomes = []
    for _ in range(6):
        with only_admins(ADMIN_USERNAME, "ac_racer"):
            barrier = threading.Barrier(2)
            results = [None, None]

            def demote(i, who, headers, victim_id, password):
                barrier.wait()
                results[i] = clients[i].put(f"/api/users/{victim_id}", json={"role": "SOC Analyst", **_confirm(password)}, headers=headers)

            threads = [
                threading.Thread(target=demote, args=(0, "boot", boot_headers, other["user_id"], ADMIN_PASSWORD)),
                threading.Thread(target=demote, args=(1, "racer", other["headers"], boot_id, other["password"])),
            ]
            [t.start() for t in threads]
            [t.join(30) for t in threads]
            statuses = sorted(r.status_code for r in results)
            assert statuses[0] == 200 and statuses[1] in (400, 403), [(r.status_code, r.text) for r in results]
            from backend.models import User
            db = _db()
            try:
                admins = [u.username for u in db.query(User).filter(User.is_active.is_(True), User.is_service_account.is_(False)).all()
                          if rbac.role_level(u.role) == "admin"]
            finally:
                db.close()
            assert len(admins) == 1, admins  # the loser lost their rights, the winner is still an administrator
            outcomes.append(admins[0])
    assert len(outcomes) == 6


# =====================================================================================================================
# (d) Step-up for sensitive changes to another administrator
# =====================================================================================================================
def test_changing_another_administrator_needs_the_acting_admins_own_password(client, admin_h):
    actor = provision(client, admin_h, "ac_actor", role="Admin")
    victim = provision(client, admin_h, "ac_victim", role="Admin", password="Another-Long-Victim-Passphrase-27")
    url = f"/api/users/{victim['user_id']}"

    missing = client.put(url, json={"role": "SOC Analyst"}, headers=actor["headers"])
    assert missing.status_code == 428 and code_of(missing) == "step_up_required"
    wrong = client.put(url, json={"role": "SOC Analyst", **_confirm("not-my-password-1234567")}, headers=actor["headers"])
    assert wrong.status_code == 403 and code_of(wrong) == "step_up_failed"
    victims_password = client.put(url, json={"role": "SOC Analyst", **_confirm(victim["password"])}, headers=actor["headers"])
    assert victims_password.status_code == 403  # the TARGET's password is not the actor's confirmation
    assert stored("ac_victim")["role"] == "Admin"

    ok = client.put(url, json={"role": "SOC Analyst", **_confirm(actor["password"])}, headers=actor["headers"])
    assert ok.status_code == 200 and ok.json()["role"] == "SOC Analyst"
    assert stored("ac_victim")["role"] == "SOC Analyst"

    # The demoted administrator's old token lost its power immediately (role is re-read on every request).
    assert client.get("/api/users", headers=victim["headers"]).status_code == 403

    # Audit: accepted change (who, target, old -> new) and the rejected attempts.
    entry = [r for r in rbac_logs(by="ac_actor") if r.target == "ac_victim" and r.details.get("changes")][-1]
    assert entry.level == "WARNING" and entry.details["changes"]["role"] == {"from": "Admin", "to": "SOC Analyst"}
    assert entry.details["step_up"] is True and entry.details["target_was_admin"] is True
    denied = [r.details["code"] for r in rbac_logs(by="ac_actor", outcome="denied") if r.target == "ac_victim"]
    assert denied.count("step_up_required") >= 1 and denied.count("step_up_failed") >= 2


def test_every_sensitive_action_on_another_admin_is_step_up_gated(client, admin_h):
    actor = provision(client, admin_h, "ac_actor2", role="Admin")
    victim = provision(client, admin_h, "ac_victim2", role="Admin")
    uid = victim["user_id"]
    gated = [
        ("put", f"/api/users/{uid}", {"is_active": False}),
        ("put", f"/api/users/{uid}", {"compromised_reset_required": True}),
        ("post", f"/api/users/{uid}/reset-password", None),
        ("post", f"/api/users/{uid}/flag-compromised", None),
    ]
    before = stored("ac_victim2")
    for method, url, body in gated:
        res = getattr(client, method)(url, headers=actor["headers"], **({"json": body} if body else {}))
        assert res.status_code == 428, (url, body, res.text)
    assert stored("ac_victim2") == before  # nothing happened, not even a password reset

    with_confirmation = _confirm(actor["password"])
    res = client.post(f"/api/users/{uid}/reset-password", headers=actor["headers"], json=with_confirmation)
    assert res.status_code == 200 and res.json()["temporary_password"]
    assert stored("ac_victim2")["password_hash"] != before["password_hash"]
    assert client.post(f"/api/users/{uid}/flag-compromised", headers=actor["headers"], json=with_confirmation).status_code == 200
    assert client.put(f"/api/users/{uid}", headers=actor["headers"], json={"is_active": False, **with_confirmation}).status_code == 200
    assert stored("ac_victim2")["is_active"] is False
    # Re-enabling an administrator is gated too.
    assert client.put(f"/api/users/{uid}", headers=actor["headers"], json={"is_active": True}).status_code == 428
    assert client.put(f"/api/users/{uid}", headers=actor["headers"], json={"is_active": True, **with_confirmation}).status_code == 200
    resets = [r for r in rbac_logs(by="ac_actor2") if r.target == "ac_victim2" and "reset the password" in r.message]
    assert resets and resets[-1].level == "WARNING" and resets[-1].details["step_up"] is True


def test_granting_the_admin_role_to_an_existing_account_needs_step_up(client, admin_h):
    actor = provision(client, admin_h, "ac_granter", role="Admin")
    analyst = provision(client, admin_h, "ac_promotee", role="SOC Analyst")
    url = f"/api/users/{analyst['user_id']}"
    assert client.put(url, json={"role": "Admin"}, headers=actor["headers"]).status_code == 428
    assert client.put(url, json={"role": "Security Engineer"}, headers=actor["headers"]).status_code == 200  # no step-up
    assert client.put(url, json={"role": "Admin", **_confirm("wrong-password-12345678")}, headers=actor["headers"]).status_code == 403
    assert stored("ac_promotee")["role"] == "Security Engineer"
    ok = client.put(url, json={"role": "admin", **_confirm(actor["password"])}, headers=actor["headers"])
    assert ok.status_code == 200 and ok.json()["role"] == "Admin"  # stored with the canonical spelling
    grant = [r for r in rbac_logs(by="ac_granter") if r.target == "ac_promotee" and r.details.get("grants_admin")]
    assert grant and grant[-1].level == "WARNING"


def test_ordinary_changes_to_non_admins_do_not_need_a_confirmation_but_a_wrong_one_is_still_refused(client, admin_h):
    target = provision(client, admin_h, "ac_plain", role="SOC Analyst")
    url = f"/api/users/{target['user_id']}"
    assert client.put(url, json={"role": "Security Engineer"}, headers=admin_h).status_code == 200
    assert client.put(url, json={"is_active": False}, headers=admin_h).status_code == 200
    assert client.put(url, json={"is_active": True}, headers=admin_h).status_code == 200
    assert client.post(f"/api/users/{target['user_id']}/unlock", headers=admin_h).status_code == 200
    res = client.put(url, json={"role": "SOC Analyst", **_confirm("not-the-admin-password-1")}, headers=admin_h)
    assert res.status_code == 403 and stored("ac_plain")["role"] == "Security Engineer"
    assert client.post(f"/api/users/{target['user_id']}/reset-password", headers=admin_h).status_code == 200


def test_step_up_failures_are_throttled(client, admin_h):
    actor = provision(client, admin_h, "ac_throttle", role="Admin")
    victim = provision(client, admin_h, "ac_throttled", role="Admin")
    url = f"/api/users/{victim['user_id']}"
    for _ in range(ratelimit.PAIR_MAX_FAILURES):
        assert client.put(url, json={"is_active": False, **_confirm("guess-guess-guess-guess1")}, headers=actor["headers"]).status_code == 403
    locked = client.put(url, json={"is_active": False, **_confirm(actor["password"])}, headers=actor["headers"])
    assert locked.status_code == 429 and code_of(locked) == "step_up_throttled" and "Retry-After" in locked.headers
    assert stored("ac_throttled")["is_active"] is True


def test_step_up_with_mfa_needs_a_fresh_code_that_cannot_be_replayed(client, admin_h):
    from backend.crypto import encrypt_value
    from backend.models import User

    actor = provision(client, admin_h, "ac_mfa_actor", role="Admin")
    victim = provision(client, admin_h, "ac_mfa_victim", role="Admin")
    secret = pyotp.random_base32()
    db = _db()
    try:
        row = db.query(User).filter(User.username == "ac_mfa_actor").first()
        row.mfa_enabled, row.mfa_secret = True, encrypt_value(secret)
        db.commit()
    finally:
        db.close()
    url = f"/api/users/{victim['user_id']}"
    body = {"is_active": False}
    assert client.put(url, json=body, headers=actor["headers"]).status_code == 428
    assert client.put(url, json={**body, **_confirm(actor["password"])}, headers=actor["headers"]).status_code == 403  # no code
    assert client.put(url, json={**body, **_confirm(actor["password"], "000000")}, headers=actor["headers"]).status_code == 403
    code = pyotp.TOTP(secret).now()
    assert client.put(url, json={**body, **_confirm("wrong-password-123456789", code)}, headers=actor["headers"]).status_code == 403
    ok = client.put(url, json={**body, **_confirm(actor["password"], code)}, headers=actor["headers"])
    assert ok.status_code == 200, ok.text
    replay = client.put(url, json={"is_active": True, **_confirm(actor["password"], code)}, headers=actor["headers"])
    assert replay.status_code == 403 and stored("ac_mfa_victim")["is_active"] is False  # the used code is rejected


def test_deleting_or_creating_an_admin_is_audited_and_gated(client, admin_h, monkeypatch):
    # Both are logged at WARNING; provisioning and deleting send the acting admin's confirmation.
    provision(client, admin_h, "ac_del_a", role="Admin")
    uid = stored_id("ac_del_a")
    assert client.request("DELETE", f"/api/users/{uid}", headers=admin_h, json=_confirm()).status_code == 200
    deleted = [r for r in rbac_logs() if r.target == "ac_del_a" and "deleted account" in r.message]
    assert deleted and deleted[-1].level == "WARNING" and deleted[-1].details["target_was_admin"] is True
    made = [r for r in rbac_logs() if r.target == "ac_del_a" and "provisioned" in r.message]
    assert made and made[-1].level == "WARNING" and made[-1].details["grants_admin"] is True

    # Both need the acting admin's own password (the policy constants are on by default; pinned here explicitly).
    monkeypatch.setattr(rbac, "STEP_UP_ON_ADMIN_CREATE", True)
    monkeypatch.setattr(rbac, "STEP_UP_ON_ADMIN_DELETE", True)
    CREATED.append("ac_del_b")
    refused = client.post("/api/users", json={"username": "ac_del_b", "role": "Admin"}, headers=admin_h)
    assert refused.status_code == 428 and stored("ac_del_b") is None
    created = client.post("/api/users", json={"username": "ac_del_b", "role": "Admin", **_confirm()}, headers=admin_h)
    assert created.status_code == 201
    assert client.post("/api/users", json={"username": "ac_del_c", "role": "SOC Analyst"}, headers=admin_h).status_code == 201
    CREATED.append("ac_del_c")
    uid = created.json()["user_id"]
    assert client.delete(f"/api/users/{uid}", headers=admin_h).status_code == 428
    assert stored("ac_del_b") is not None
    assert client.request("DELETE", f"/api/users/{uid}", headers=admin_h, json=_confirm()).status_code == 200
    assert stored("ac_del_b") is None
    assert client.delete(f"/api/users/{stored_id('ac_del_c')}", headers=admin_h).status_code == 200  # non-admin: no step-up


def stored_id(username):
    from backend.models import User
    db = _db()
    try:
        return db.query(User).filter(User.username == username).first().user_id
    finally:
        db.close()


# =====================================================================================================================
# (c) Service / AI-agent accounts
# =====================================================================================================================
def test_service_accounts_can_never_be_promoted_or_converted(client, admin_h):
    acct = service_account(client, admin_h, "ac-agent-1")
    uid = acct["user_id"]
    assert acct["role"] == "AI Agent"
    for role in ("Admin", "admin", "SOC Analyst", "Security Engineer", "AI Agent", "Sys Admin", "Supreme Overlord"):
        res = client.put(f"/api/users/{uid}", json={"role": role, **_confirm()}, headers=admin_h)
        assert res.status_code == 400, (role, res.text)
    for body in ({"is_service_account": False}, {"role": "SOC Analyst", "is_service_account": False}, {"api_key_hash": "x"},
                 {"username": "renamed"}, {"mfa_enabled": True}, {"password_hash": "x"}):
        res = client.put(f"/api/users/{uid}", json=body, headers=admin_h)
        assert res.status_code == 422 and code_of(res) == "fields_not_allowed", (body, res.text)
    after = stored("ac-agent-1")
    assert after["role"] == "AI Agent" and after["is_service_account"] is True
    # Creating a person with a service role, or a service account with an admin role, is refused.
    for role in ("AI Agent", "Service Account"):
        assert client.post("/api/users", json={"username": "ac_not_an_agent", "role": role}, headers=admin_h).status_code == 400
    assert stored("ac_not_an_agent") is None
    res = client.post("/api/users/service-accounts", json={"username": "ac-agent-2", "role": "Admin"}, headers=admin_h)
    assert res.status_code == 422 and stored("ac-agent-2") is None
    res = client.post("/api/users/service-accounts", json={"username": "ac-agent-2", "is_service_account": False}, headers=admin_h)
    assert res.status_code == 422 and stored("ac-agent-2") is None
    # A person cannot be turned into a service account either.
    human = provision(client, admin_h, "ac_human", role="SOC Analyst")
    res = client.put(f"/api/users/{human['user_id']}", json={"is_service_account": True}, headers=admin_h)
    assert res.status_code == 422 and stored("ac_human")["is_service_account"] is False


def test_service_account_only_gets_key_status_and_policy_management(client, admin_h):
    acct = service_account(client, admin_h, "ac-agent-3")
    uid = acct["user_id"]
    assert code_of(client.post(f"/api/users/{uid}/reset-password", headers=admin_h)) == "service_account_no_password"
    assert code_of(client.post(f"/api/users/{uid}/flag-compromised", headers=admin_h)) == "service_account_no_password"
    assert code_of(client.post(f"/api/users/{uid}/unlock", headers=admin_h)) == "service_account_no_password"
    assert code_of(client.put(f"/api/users/{uid}", json={"compromised_reset_required": True}, headers=admin_h)) == "service_account_no_password"
    assert client.put(f"/api/users/{uid}/service-policy", json={"ip_allowlist": ["203.0.113.0/24"]}, headers=admin_h).status_code == 200
    assert client.post(f"/api/users/{uid}/rotate-api-key", headers=admin_h).status_code == 200
    assert client.put(f"/api/users/{uid}", json={"is_active": False}, headers=admin_h).status_code == 200
    assert client.delete(f"/api/users/{uid}", headers=admin_h).status_code == 200
    human = provision(client, admin_h, "ac_human2", role="SOC Analyst")
    assert code_of(client.post(f"/api/users/{human['user_id']}/rotate-api-key", headers=admin_h)) == "not_a_service_account"
    assert code_of(client.put(f"/api/users/{human['user_id']}/service-policy", json={}, headers=admin_h)) == "not_a_service_account"


def test_agent_credentials_cannot_reach_any_account_management_endpoint(client, admin_h):
    acct = service_account(client, admin_h, "ac-agent-4")
    victim = provision(client, admin_h, "ac_untouchable", role="SOC Analyst")
    key = acct["api_key"]
    before_users = {u["username"]: u["role"] for u in client.get("/api/users", headers=admin_h).json()}
    uid, vid = acct["user_id"], victim["user_id"]
    carriers = [
        {"X-Phantom-Agent-Key": key},
        {"Authorization": f"Bearer {key}"},
        {"Authorization": f"Bearer {key}", "X-Phantom-Agent-Key": key},
        bearer("ac-agent-4"),  # a JWT forged for the agent's own username (e.g. by someone holding the signing key)
        bearer("ac-agent-4", role="Admin"),  # ... even claiming the admin role
    ]
    calls = [
        ("get", "/api/users", None), ("get", "/api/users/roles", None),
        ("post", "/api/users", {"username": "ac_by_agent", "role": "Admin"}),
        ("post", "/api/users/service-accounts", {"username": "ac-by-agent"}),
        ("put", f"/api/users/{uid}", {"role": "Admin"}), ("put", f"/api/users/{vid}", {"role": "Admin"}),
        ("put", f"/api/users/{vid}", {"is_active": False}),
        ("post", f"/api/users/{vid}/reset-password", None), ("post", f"/api/users/{vid}/flag-compromised", None),
        ("post", f"/api/users/{vid}/unlock", None), ("post", f"/api/users/{uid}/rotate-api-key", None),
        ("put", f"/api/users/{uid}/service-policy", {"clear_expiry": True}), ("delete", f"/api/users/{vid}", None),
        ("delete", f"/api/users/{uid}", None),
    ]
    for headers in carriers:
        for method, url, body in calls:
            res = getattr(client, method)(url, headers=headers, **({"json": body} if body is not None else {}))
            assert res.status_code in (401, 403), (headers, method, url, res.status_code)
    after_users = {u["username"]: u["role"] for u in client.get("/api/users", headers=admin_h).json()}
    assert after_users == before_users
    assert stored("ac_by_agent") is None and stored("ac-by-agent") is None


def test_a_corrupted_agent_row_with_an_admin_role_still_cannot_administer(client, admin_h):
    """Defence in depth: even if a service account row somehow carried the Admin role, it is no administrator."""
    from backend.models import User
    acct = service_account(client, admin_h, "ac-agent-5")
    db = _db()
    try:
        db.query(User).filter(User.username == "ac-agent-5").update({"role": "Admin"})
        db.commit()
    finally:
        db.close()
    assert client.get("/api/users", headers=bearer("ac-agent-5")).status_code == 403
    assert client.get("/api/users", headers={"X-Phantom-Agent-Key": acct["api_key"]}).status_code == 401
    row = [u for u in client.get("/api/users", headers=admin_h).json() if u["username"] == "ac-agent-5"][0]
    assert row["account_actions"]["change_role"]["allowed"] is False
    # and it never counts as one of the platform's administrators
    from backend.routers.users import _active_admin_count
    db = _db()
    try:
        assert _active_admin_count(db) == _active_admin_count(db, excluding_user_id=acct["user_id"])
    finally:
        db.close()


# =====================================================================================================================
# (e) Role validation and (f) mass assignment
# =====================================================================================================================
def test_roles_are_validated_server_side_on_create_and_update(client, admin_h):
    target = provision(client, admin_h, "ac_roles", role="SOC Analyst")
    url = f"/api/users/{target['user_id']}"
    for bad in ("Supreme Overlord", "Administrator", "Sys Admin", "SOC Lead / Admin", "", "   ", "A" * 61, "Adm1n", "AI Agent"):
        assert client.put(url, json={"role": bad}, headers=admin_h).status_code in (400, 422), bad
        if bad:  # an omitted or empty role on create falls back to the least-privileged default, as before
            assert client.post("/api/users", json={"username": "ac_badrole", "role": bad}, headers=admin_h).status_code in (400, 422), bad
    assert stored("ac_badrole") is None and stored("ac_roles")["role"] == "SOC Analyst"
    CREATED.append("ac_default_role")
    default = client.post("/api/users", json={"username": "ac_default_role", "role": ""}, headers=admin_h)
    assert default.status_code == 201 and default.json()["role"] == "SOC Analyst"
    legacy = client.put(url, json={"role": "Tier 2 Analyst (Senior Responder)"}, headers=admin_h)
    assert legacy.status_code == 200 and legacy.json()["role"] == "Tier 2 Analyst (Senior Responder)"
    catalog = client.get("/api/users/roles", headers=admin_h).json()
    assert [r["role"] for r in catalog] == list(rbac.assignable_roles())
    assert "AI Agent" not in [r["role"] for r in catalog]


def test_only_whitelisted_fields_can_be_updated_and_attempts_are_audited(client, admin_h):
    target = provision(client, admin_h, "ac_mass", role="SOC Analyst")
    url = f"/api/users/{target['user_id']}"
    before = stored("ac_mass")
    bodies = [
        {"role": "Security Engineer", "is_service_account": True},
        {"role": "Security Engineer", "username": "someone_else"},
        {"role": "Security Engineer", "password_hash": "$argon2id$x"},
        {"is_active": True, "mfa_enabled": True, "mfa_secret": "JBSWY3DPEHPK3PXP"},
        {"role": "Security Engineer", "user_id": 1, "must_change_password": False, "failed_login_attempts": 0},
        {"role": "Security Engineer", "api_key_hash": "x", "api_key_prefix": "phk_00000000"},
        {"__class__": "User"},
    ]
    for body in bodies:
        res = client.put(url, json=body, headers=admin_h)
        assert res.status_code == 422 and code_of(res) == "fields_not_allowed", (body, res.text)
    assert stored("ac_mass") == before  # not even the whitelisted role in the same body was applied
    attempts = [r for r in rbac_logs(by=ADMIN_USERNAME, code="fields_not_allowed") if r.target == f"#{target['user_id']}"]
    assert len(attempts) >= len(bodies) and "is_service_account" in attempts[-len(bodies)].details["attempted"]["fields"]
    res = client.post("/api/users", json={"username": "ac_mass2", "role": "SOC Analyst", "is_active": False, "must_change_password": False}, headers=admin_h)
    assert res.status_code == 422 and stored("ac_mass2") is None
    # Nested confirmation payloads are strict as well.
    res = client.put(url, json={"role": "Security Engineer", "confirmation": {"current_password": "x", "is_admin": True}}, headers=admin_h)
    assert res.status_code == 422


# =====================================================================================================================
# Console contract: GET /api/users carries what each row allows
# =====================================================================================================================
def test_user_list_reports_what_the_signed_in_admin_may_do(client, admin_h):
    other = provision(client, admin_h, "ac_listed", role="Admin")
    analyst = provision(client, admin_h, "ac_listed_analyst", role="SOC Analyst")
    acct = service_account(client, admin_h, "ac-agent-6")
    rows = {u["username"]: u for u in client.get("/api/users", headers=other["headers"]).json()}

    self_row = rows["ac_listed"]["account_actions"]
    assert not self_row["change_role"]["allowed"] and "own role" in self_row["change_role"]["reason"]
    assert not self_row["delete"]["allowed"] and not self_row["set_active"]["allowed"] and not self_row["reset_password"]["allowed"]

    boot = rows[ADMIN_USERNAME]["account_actions"]
    assert not boot["delete"]["allowed"] and not boot["set_active"]["allowed"] and not boot["change_role"]["allowed"]
    assert boot["reset_password"]["allowed"] and boot["reset_password"]["step_up"] is True

    plain = rows["ac_listed_analyst"]["account_actions"]
    assert plain["delete"]["allowed"] and not plain["delete"]["step_up"] and plain["reset_password"]["allowed"]
    assert not plain["rotate_key"]["allowed"]

    agent = rows["ac-agent-6"]["account_actions"]
    assert not agent["change_role"]["allowed"] and not agent["reset_password"]["allowed"] and not agent["set_active"]["step_up"]
    assert agent["rotate_key"]["allowed"] and agent["service_policy"]["allowed"] and agent["delete"]["allowed"]
    assert analyst["user_id"] and acct["user_id"]
    # Only the list carries the field.
    assert client.get("/api/auth/me", headers=other["headers"]).json().get("account_actions") is None


def test_an_unlock_by_an_admin_also_clears_the_step_up_throttle(client, admin_h):
    victim = provision(client, admin_h, "ac_unlockme", role="Admin")
    actor = provision(client, admin_h, "ac_unlocker", role="Admin")
    for _ in range(ratelimit.PAIR_MAX_FAILURES):
        client.put(f"/api/users/{victim['user_id']}", json={"is_active": False, **_confirm("nope-nope-nope-nope-1")}, headers=actor["headers"])
    assert ratelimit.pair_locked("stepup", "ac_unlocker", "testclient")
    assert client.post(f"/api/users/{actor['user_id']}/unlock", headers=victim["headers"]).status_code == 200
    assert not ratelimit.pair_locked("stepup", "ac_unlocker", "testclient")


# =====================================================================================================================
# Review fixes: delete over POST, no-op role resend, step-up counters separate from sign-in counters
# =====================================================================================================================
def test_post_delete_route_takes_the_confirmation_in_its_body(client, admin_h):
    """DELETE with a body is dropped by some proxies; POST /users/{id}/delete does the same thing with a safe body."""
    victim = provision(client, admin_h, "ac_postdel", role="Admin")
    url = f"/api/users/{victim['user_id']}/delete"
    missing = client.post(url, headers=admin_h)
    assert missing.status_code == 428 and code_of(missing) == "step_up_required" and stored("ac_postdel") is not None
    wrong = client.post(url, json=_confirm("not-the-admin-password-1"), headers=admin_h)
    assert wrong.status_code == 403 and code_of(wrong) == "step_up_failed" and stored("ac_postdel") is not None
    ok = client.post(url, json=_confirm(), headers=admin_h)
    assert ok.status_code == 200 and stored("ac_postdel") is None
    deleted = [r for r in rbac_logs() if r.target == "ac_postdel" and "deleted account" in r.message]
    assert deleted and deleted[-1].level == "WARNING" and deleted[-1].details["step_up"] is True
    # Same policy as DELETE: nobody deletes themselves or the bootstrap admin, and non-admin targets need no confirmation.
    assert client.post(f"/api/users/{me(client, admin_h)['user_id']}/delete", json=_confirm(), headers=admin_h).status_code == 400
    plain = provision(client, admin_h, "ac_postdel_plain", role="SOC Analyst")
    assert client.post(f"/api/users/{plain['user_id']}/delete", headers=admin_h).status_code == 200
    # A non-admin cannot use it either.
    other = provision(client, admin_h, "ac_postdel_other", role="SOC Analyst")
    assert client.post(f"/api/users/{other['user_id']}/delete", headers=other["headers"]).status_code == 403


def test_the_bootstrap_admin_cannot_be_deleted_even_with_a_valid_confirmation(client, admin_h):
    actor = provision(client, admin_h, "ac_boot_killer", role="Admin")
    boot_id = me(client, admin_h)["user_id"]
    assert client.post(f"/api/users/{boot_id}/delete", json=_confirm(actor["password"]), headers=actor["headers"]).status_code == 400
    res = client.request("DELETE", f"/api/users/{boot_id}", json=_confirm(actor["password"]), headers=actor["headers"])
    assert res.status_code == 400 and code_of(res) == "bootstrap_protected"


def _set_role_directly(username, role):
    from backend.models import User
    db = _db()
    try:
        db.query(User).filter(User.username == username).update({"role": role})
        db.commit()
    finally:
        db.close()


def test_resending_the_current_role_is_a_harmless_no_op(client, admin_h):
    legacy_admin = provision(client, admin_h, "ac_legacy_admin", role="SOC Analyst")
    legacy_human = provision(client, admin_h, "ac_legacy_human", role="SOC Analyst")
    _set_role_directly("ac_legacy_admin", "Sys Admin")  # a legacy administrator alias that can no longer be assigned
    _set_role_directly("ac_legacy_human", "Tier 2 Analyst (Senior Responder)")
    before = len(rbac_logs())

    # Another admin resending the stored role (even with different spacing) changes nothing, needs no step-up, writes no audit row.
    for uid, role in ((legacy_admin["user_id"], "Sys Admin"), (legacy_admin["user_id"], " Sys   Admin "),
                      (legacy_human["user_id"], "Tier 2 Analyst (Senior Responder)")):
        res = client.put(f"/api/users/{uid}", json={"role": role}, headers=admin_h)
        assert res.status_code == 200, (role, res.text)
    assert stored("ac_legacy_admin")["role"] == "Sys Admin" and stored("ac_legacy_human")["role"] == "Tier 2 Analyst (Senior Responder)"
    assert len(rbac_logs()) == before

    # The same form also sending another field still applies only that field.
    res = client.put(f"/api/users/{legacy_human['user_id']}", json={"role": "Tier 2 Analyst (Senior Responder)", "is_active": False}, headers=admin_h)
    assert res.status_code == 200 and stored("ac_legacy_human")["is_active"] is False
    assert stored("ac_legacy_human")["role"] == "Tier 2 Analyst (Senior Responder)"

    # A real change is still validated: a legacy administrator name is never assignable to someone else.
    res = client.put(f"/api/users/{legacy_human['user_id']}", json={"role": "Sys Admin"}, headers=admin_h)
    assert res.status_code == 400 and code_of(res) == "legacy_admin_alias"
    res = client.put(f"/api/users/{legacy_admin['user_id']}", json={"role": "Administrator"}, headers=admin_h)
    assert res.status_code == 400 and code_of(res) == "legacy_admin_alias"
    # Moving the legacy admin to a canonical role is a normal, step-up-gated demotion.
    res = client.put(f"/api/users/{legacy_admin['user_id']}", json={"role": "SOC Analyst"}, headers=admin_h)
    assert res.status_code == 428
    res = client.put(f"/api/users/{legacy_admin['user_id']}", json={"role": "SOC Analyst", **_confirm()}, headers=admin_h)
    assert res.status_code == 200 and stored("ac_legacy_admin")["role"] == "SOC Analyst"


def test_the_pure_policy_treats_the_stored_role_as_unchanged():
    assert rbac.role_unchanged("Sys Admin", "Sys Admin") and rbac.role_unchanged("Sys  Admin", " Sys Admin")
    assert rbac.role_unchanged("anything", None)
    assert not rbac.role_unchanged("Sys Admin", "sys admin")  # exact spelling: a case change is a real change
    legacy = Subject(20, "legacy", "Sys Admin")
    assert decide(Action.CHANGE_ROLE, ADMIN, legacy, new_role="Sys Admin").allowed
    assert not decide(Action.CHANGE_ROLE, ADMIN, legacy, new_role="Sys Admin").step_up


def test_wrong_step_up_confirmations_do_not_touch_the_sign_in_counters(client, admin_h):
    actor = provision(client, admin_h, "ac_stepup_login", role="Admin")
    victim = provision(client, admin_h, "ac_stepup_login_v", role="Admin")
    url = f"/api/users/{victim['user_id']}"
    ratelimit.reset_all()
    for _ in range(ratelimit.STEPUP_MAX_FAILURES):
        assert client.put(url, json={"is_active": False, **_confirm("guess-guess-guess-guess1")}, headers=actor["headers"]).status_code == 403
    assert client.put(url, json={"is_active": False, **_confirm(actor["password"])}, headers=actor["headers"]).status_code == 429
    uh = ratelimit._uh("ac_stepup_login")
    assert ratelimit.limiter.count(f"fail:user:{uh}", ratelimit.USER_WINDOW) == 0
    assert ratelimit.limiter.count("fail:ip:testclient", ratelimit.IP_WINDOW) == 0
    assert not ratelimit.pair_locked("login", "ac_stepup_login", "testclient") and not ratelimit.ip_blocked("testclient")
    assert ratelimit.username_delay("ac_stepup_login") == 0.0
    login = client.post("/api/auth/login", json={"username": "ac_stepup_login", "password": actor["password"]})
    assert login.status_code == 200, login.text  # the admin's real sign-in is unaffected
    assert stored("ac_stepup_login_v")["is_active"] is True


def test_wrong_sign_ins_do_not_lock_step_up_confirmations(client, admin_h):
    actor = provision(client, admin_h, "ac_login_stepup", role="Admin")
    victim = provision(client, admin_h, "ac_login_stepup_v", role="Admin")
    for _ in range(ratelimit.PAIR_MAX_FAILURES):
        assert client.post("/api/auth/login", json={"username": "ac_login_stepup", "password": "wrong-wrong-wrong-1"}).status_code in (401, 429)
    assert ratelimit.stepup_retry_after("ac_login_stepup", "testclient") == 0
    res = client.put(f"/api/users/{victim['user_id']}", json={"is_active": False, **_confirm(actor["password"])}, headers=actor["headers"])
    assert res.status_code == 200


def test_step_up_retry_after_is_the_real_remaining_lock_time(client, admin_h, monkeypatch):
    actor = provision(client, admin_h, "ac_retry", role="Admin")
    victim = provision(client, admin_h, "ac_retry_v", role="Admin")
    url = f"/api/users/{victim['user_id']}"
    for _ in range(ratelimit.STEPUP_MAX_FAILURES):
        client.put(url, json={"is_active": False, **_confirm("guess-guess-guess-guess1")}, headers=actor["headers"])
    locked = client.put(url, json={"is_active": False, **_confirm(actor["password"])}, headers=actor["headers"])
    assert locked.status_code == 429
    header = int(locked.headers["Retry-After"])
    assert ratelimit.STEPUP_WINDOW - 30 <= header <= ratelimit.STEPUP_WINDOW + 2  # the whole window is still ahead
    assert "15 minute" in locked.json()["detail"]["message"]

    import time as real_time
    start = real_time.time()
    fake = types_namespace(lambda: start + 600)
    monkeypatch.setattr(ratelimit, "time", fake)
    assert abs(ratelimit.stepup_retry_after("ac_retry", "testclient") - (ratelimit.STEPUP_WINDOW - 600)) <= 3
    monkeypatch.setattr(ratelimit, "time", types_namespace(lambda: start + ratelimit.STEPUP_WINDOW + 5))
    assert ratelimit.stepup_retry_after("ac_retry", "testclient") == 0  # the lock expired


def types_namespace(clock):
    import time as real_time
    import types
    return types.SimpleNamespace(time=clock, monotonic_ns=real_time.monotonic_ns)


def test_step_up_failures_from_many_addresses_lock_the_admin_for_confirmations_only(client, admin_h):
    ratelimit.reset_all()
    for i in range(ratelimit.STEPUP_USER_MAX_FAILURES):
        ratelimit.stepup_register_failure("ac_many_ips", f"198.51.100.{i}")
    assert ratelimit.stepup_retry_after("ac_many_ips", "203.0.113.77") > 0  # a fresh address is locked too
    assert ratelimit.stepup_retry_after("someone_else", "203.0.113.77") == 0
    assert not ratelimit.pair_locked("login", "ac_many_ips", "203.0.113.77")
    assert ratelimit.limiter.count(f"fail:user:{ratelimit._uh('ac_many_ips')}", ratelimit.USER_WINDOW) == 0
    ratelimit.clear_username("ac_many_ips")  # an admin unlock forgets it
    assert ratelimit.stepup_retry_after("ac_many_ips", "203.0.113.77") == 0
