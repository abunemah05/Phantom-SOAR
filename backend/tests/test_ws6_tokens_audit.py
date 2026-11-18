"""WS6 tests: ingest tokens, revocation, service accounts, audit trail, TOTP replay, MFA policy, bootstrap, validation."""
import json
import os
import stat
import time
import types
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from backend import ratelimit
from backend.tests.ws6_helpers import (  # noqa: F401  (fixtures are used by name)
    ADMIN_PASSWORD, STRONG_PASSWORD, _clean_state, _mount_ingest_router, admin_h, admin_name, bearer, client_from, make_user,
)

HOOK = {"rule": {"id": "99001", "level": 3, "description": "ws6 test event"}, "agent": {"id": "001", "name": "ws6-host"}}


def _naive_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def db():
    from backend.database import SessionLocal
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def _cleanup_ingest_tokens(client):
    yield
    from backend.database import SessionLocal
    from backend.security_models import IngestToken
    with SessionLocal() as session:
        session.query(IngestToken).filter(IngestToken.name.like("ws6-%")).delete(synchronize_session=False)
        session.commit()


def create_token(client, admin_h, name, **body):
    res = client.post("/api/ingest-tokens", headers=admin_h, json={"name": name, **body})
    assert res.status_code == 201, res.text
    return res.json()


def hook_headers(token):
    return {"X-Phantom-Ingest-Token": token}


# --- ingest tokens ----------------------------------------------------------------------------------
def test_ingest_token_lifecycle(client, admin_h, monkeypatch):
    monkeypatch.delenv("PHANTOM_INGEST_TOKEN", raising=False)
    created = create_token(client, admin_h, "ws6-wazuh-prod")
    token = created["token"]
    assert token.startswith("phi_") and created["status"] == "active" and created["last_used_at"] is None
    assert created["token_prefix"] == "_".join(token.split("_", 2)[:2])

    listing = client.get("/api/ingest-tokens", headers=admin_h)
    assert listing.status_code == 200
    mine = next(t for t in listing.json() if t["name"] == "ws6-wazuh-prod")
    assert "token" not in mine and "token_hash" not in mine and token not in listing.text

    ok = client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(token))
    assert ok.status_code == 201, ok.text
    after = next(t for t in client.get("/api/ingest-tokens", headers=admin_h).json() if t["name"] == "ws6-wazuh-prod")
    assert after["last_used_at"] is not None

    # Right prefix, wrong secret; and a token for another prefix.
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(token[:-4] + "XXXX")).status_code == 401
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers("phi_deadbeef_" + "a" * 43)).status_code == 401
    assert client.post("/api/webhooks/wazuh", json=HOOK).status_code == 401

    revoked = client.post(f"/api/ingest-tokens/{created['id']}/revoke", headers=admin_h)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    # With no credential left at all, ingestion is disabled rather than open.
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(token)).status_code == 503
    other = create_token(client, admin_h, "ws6-second-sender")
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(token)).status_code == 401  # revoked stays dead
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(other["token"])).status_code == 201


def test_ingest_token_expiry_and_admin_only(client, admin_h, db, monkeypatch):
    monkeypatch.delenv("PHANTOM_INGEST_TOKEN", raising=False)
    from backend.security_models import IngestToken

    created = create_token(client, admin_h, "ws6-expiring", expires_in_days=1)
    assert created["expires_at"]
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(created["token"])).status_code == 201
    row = db.query(IngestToken).filter_by(id=created["id"]).first()
    row.expires_at = _naive_now() - timedelta(minutes=1)
    db.commit()
    create_token(client, admin_h, "ws6-keeps-ingest-enabled")
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(created["token"])).status_code == 401
    assert next(t for t in client.get("/api/ingest-tokens", headers=admin_h).json() if t["id"] == created["id"])["status"] == "expired"

    make_user(client, admin_h, "ws6_ingest_analyst")
    analyst = bearer("ws6_ingest_analyst")
    assert client.post("/api/ingest-tokens", headers=analyst, json={"name": "ws6-nope"}).status_code == 403
    assert client.get("/api/ingest-tokens", headers=analyst).status_code == 403
    assert client.post("/api/ingest-tokens", json={"name": "ws6-nope"}).status_code == 401
    assert client.post("/api/ingest-tokens", headers=admin_h, json={"name": "ws6-keeps-ingest-enabled"}).status_code == 400  # duplicate
    assert client.post("/api/ingest-tokens/999999/revoke", headers=admin_h).status_code == 404


def test_legacy_env_ingest_token_needs_32_characters(client, admin_h, monkeypatch):
    monkeypatch.setenv("PHANTOM_INGEST_TOKEN", "s" * 31)
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers("s" * 31)).status_code == 503  # ignored, nothing configured
    create_token(client, admin_h, "ws6-enable-ingest")
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers("s" * 31)).status_code == 401

    monkeypatch.setenv("PHANTOM_INGEST_TOKEN", "L" * 32)
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers("L" * 32)).status_code == 201
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers("L" * 31 + "x")).status_code == 401


def test_no_default_ingest_token_and_failures_are_throttled(client, admin_h, monkeypatch):
    monkeypatch.delenv("PHANTOM_INGEST_TOKEN", raising=False)
    for guess in ("", "changeme", "phantom", "test-ingest-token", "default"):
        assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(guess)).status_code in (401, 503)
    assert client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers("changeme")).status_code == 503

    create_token(client, admin_h, "ws6-throttle")
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_INGEST_FAILURES", "3/60")
    codes = [client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(f"guess-{i}")).status_code for i in range(4)]
    assert codes == [401, 401, 401, 429]


def test_webhook_requests_are_rate_limited_per_address(client, admin_h, monkeypatch):
    token = create_token(client, admin_h, "ws6-busy-sender")["token"]
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_WEBHOOKS", "2/60")
    codes = [client.post("/api/webhooks/wazuh", json=HOOK, headers=hook_headers(token)).status_code for _ in range(3)]
    assert codes == [201, 201, 429]


# --- persisted revocation ------------------------------------------------------------------------------
def test_logout_revocation_survives_restart_and_expired_rows_are_purged(client, admin_h, db):
    from backend import security
    from backend.security_models import RevokedToken

    created = make_user(client, admin_h, "ws6_revoke_user")
    login = client.post("/api/auth/login", json={"username": "ws6_revoke_user", "password": created["temporary_password"]})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    jti = security.decode_access_token(login.json()["access_token"])["jti"]
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert db.query(RevokedToken).filter_by(jti=jti).first() is not None  # persisted

    security.forget_revocation_cache()  # what a restart or another worker looks like
    assert client.get("/api/auth/me", headers=headers).status_code == 401

    db.add(RevokedToken(jti="ws6-long-expired", expires_at=_naive_now() - timedelta(hours=2)))
    db.commit()
    assert security.purge_expired_revocations() >= 1
    assert db.query(RevokedToken).filter_by(jti="ws6-long-expired").first() is None
    assert db.query(RevokedToken).filter_by(jti=jti).first() is not None  # live revocations are kept


def test_validate_security_config(monkeypatch):
    from cryptography.fernet import Fernet
    from backend import crypto
    from backend.security import SecurityConfigError, validate_security_config

    monkeypatch.setenv("PHANTOM_ENV", "production")
    monkeypatch.setenv("PHANTOM_JWT_SECRET", "short")
    monkeypatch.delenv("PHANTOM_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("PHANTOM_ENCRYPTION_KEYS", raising=False)
    try:
        with pytest.raises(SecurityConfigError) as err:
            validate_security_config()
        assert "PHANTOM_JWT_SECRET" in str(err.value) and "PHANTOM_ENCRYPTION_KEY" in str(err.value)

        monkeypatch.setenv("PHANTOM_JWT_SECRET", "j" * 40)
        with pytest.raises(SecurityConfigError) as err:
            validate_security_config()
        assert "PHANTOM_ENCRYPTION_KEY" in str(err.value) and "PHANTOM_JWT_SECRET" not in str(err.value)

        monkeypatch.setenv("PHANTOM_ENCRYPTION_KEY", Fernet.generate_key().decode())
        validate_security_config()  # complete configuration passes

        monkeypatch.setenv("PHANTOM_ENV", "development")
        monkeypatch.setenv("PHANTOM_JWT_SECRET", "short")
        monkeypatch.delenv("PHANTOM_ENCRYPTION_KEY")
        validate_security_config()  # tolerated (warning only) outside production
    finally:
        crypto.reset_cache()


def test_bootstrap_password_goes_to_a_private_file_not_the_log(tmp_path, monkeypatch, caplog, db):
    import backend.routers.auth as auth
    from backend.models import User
    from backend.security import verify_password

    target = tmp_path / "bootstrap.txt"
    monkeypatch.delenv("PHANTOM_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("PHANTOM_BOOTSTRAP_ADMIN_USERNAME", "ws6_root")
    monkeypatch.setenv("PHANTOM_BOOTSTRAP_PASSWORD_FILE", str(target))
    monkeypatch.setattr(auth, "_bootstrap_username", auth._bootstrap_username)  # restored after the test
    try:
        with caplog.at_level("DEBUG"):
            user = auth.ensure_default_user(db)
        assert user.username == "ws6_root" and user.must_change_password is True
        content = target.read_text()
        password = content.split("password: ")[1].strip()
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
        assert verify_password(password, user.password_hash)
        assert password not in caplog.text and str(target) in caplog.text  # only the path is logged
        assert auth.user_public_dict(user)["is_bootstrap_admin"] is True
    finally:
        db.query(User).filter_by(username="ws6_root").delete()
        db.commit()


def test_bootstrap_admin_flag_is_exposed(client, admin_h):
    users = client.get("/api/users", headers=admin_h).json()
    flagged = [u["username"] for u in users if u["is_bootstrap_admin"]]
    assert flagged == [admin_name()]
    assert client.get("/api/auth/me", headers=admin_h).json()["is_bootstrap_admin"] is True
    # The configured bootstrap account cannot be deleted or disabled, whatever it is called.
    boot = next(u for u in users if u["is_bootstrap_admin"])
    assert client.delete(f"/api/users/{boot['user_id']}", headers=make_admin_other(client, admin_h)).status_code == 400
    assert client.put(f"/api/users/{boot['user_id']}", json={"is_active": False}, headers=make_admin_other(client, admin_h)).status_code == 400


def make_admin_other(client, admin_h):
    make_user(client, admin_h, "ws6_second_admin", role="Admin")
    return bearer("ws6_second_admin")


# --- service accounts -----------------------------------------------------------------------------------
def _service_logs(db, username):
    from backend.models import SystemLog
    return [(entry.level, entry.details.get("outcome")) for entry in
            db.query(SystemLog).filter(SystemLog.source == "AUTH", SystemLog.target == username).order_by(SystemLog.log_id).all()]


def test_service_account_expiry_allowlist_and_audit(client, admin_h, db):
    from backend.security_models import ServiceAccountPolicy

    res = client.post("/api/users/service-accounts", headers=admin_h,
                      json={"username": "ws6-agent-a", "expires_in_days": 30, "ip_allowlist": ["198.51.100.0/24", "203.0.113.5"]})
    assert res.status_code == 201, res.text
    account = res.json()
    assert account["ip_allowlist"] == ["198.51.100.0/24", "203.0.113.5/32"] and account["expires_at"]
    key = {"X-Phantom-Agent-Key": account["api_key"]}

    inside, outside = client_from("198.51.100.77"), client_from("192.0.2.50")
    ok = inside.get("/api/auth/service-account", headers=key)
    assert ok.status_code == 200 and ok.json()["username"] == "ws6-agent-a"
    assert ok.json()["last_used_ip"] == "198.51.100.77" and ok.json()["last_used_at"]
    assert outside.get("/api/auth/service-account", headers=key).status_code == 403
    assert inside.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": account["api_key"][:-3] + "abc"}).status_code == 401

    outcomes = [o for _, o in _service_logs(db, "ws6-agent-a")]
    assert "ok" in outcomes and "ip_not_allowed" in outcomes
    from backend.models import SystemLog
    assert db.query(SystemLog).filter_by(source="AUTH", target=account["api_key_prefix"]).count() >= 1  # bad key logged by prefix

    policy = db.query(ServiceAccountPolicy).filter_by(user_id=account["user_id"]).first()
    policy.expires_at = _naive_now() - timedelta(minutes=1)
    db.commit()
    expired = inside.get("/api/auth/service-account", headers=key)
    assert expired.status_code == 401 and "expired" in expired.json()["detail"]
    assert "key_expired" in [o for _, o in _service_logs(db, "ws6-agent-a")]

    # Rotating requires choosing a new expiry once the old one has passed, and can change the allow-list.
    assert client.post(f"/api/users/{account['user_id']}/rotate-api-key", headers=admin_h).status_code == 400
    rotated = client.post(f"/api/users/{account['user_id']}/rotate-api-key", headers=admin_h,
                          json={"expires_in_days": 7, "ip_allowlist": []})
    assert rotated.status_code == 200 and rotated.json()["ip_allowlist"] == []
    assert outside.get("/api/auth/service-account", headers=key).status_code == 401  # old key dead
    assert outside.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": rotated.json()["api_key"]}).status_code == 200

    pol = client.put(f"/api/users/{account['user_id']}/service-policy", headers=admin_h, json={"clear_expiry": True, "ip_allowlist": ["192.0.2.0/24"]})
    assert pol.status_code == 200 and pol.json()["expires_at"] is None and pol.json()["ip_allowlist"] == ["192.0.2.0/24"]


def test_service_account_key_failures_are_throttled_and_prefixes_never_collide(client, admin_h, monkeypatch):
    import backend.routers.users as users_module

    first = client.post("/api/users/service-accounts", headers=admin_h, json={"username": "ws6-agent-b"}).json()
    forged_key = first["api_key_prefix"] + "_" + "z" * 43
    calls = iter([(forged_key, first["api_key_prefix"], "0" * 64)])
    real = users_module.generate_api_key
    monkeypatch.setattr(users_module, "generate_api_key", lambda: next(calls, None) or real())
    second = client.post("/api/users/service-accounts", headers=admin_h, json={"username": "ws6-agent-c"})
    assert second.status_code == 201
    assert second.json()["api_key_prefix"] != first["api_key_prefix"]  # the colliding candidate was skipped
    monkeypatch.setattr(users_module, "generate_api_key", real)

    monkeypatch.setenv("PHANTOM_RATE_LIMIT_SERVICE_KEY_FAILURES", "3/60")
    attacker = client_from("203.0.113.140")
    codes = [attacker.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": f"phk_00000000_{i}"}).status_code for i in range(4)]
    assert codes == [401, 401, 401, 429]
    assert attacker.get("/api/auth/service-account", headers={"X-Phantom-Agent-Key": first["api_key"]}).status_code == 429


def test_user_and_service_account_input_is_validated(client, admin_h):
    for bad in ("", "ab", "has space", "semi;colon", "<script>alert(1)</script>", "x" * 51, "-leading", "new\nline"):
        assert client.post("/api/users", headers=admin_h, json={"username": bad}).status_code in (400, 422), bad
        assert client.post("/api/users/service-accounts", headers=admin_h, json={"username": bad}).status_code in (400, 422), bad
    make_user(client, admin_h, "ws6_Dupe_Check")
    assert client.post("/api/users", headers=admin_h, json={"username": "WS6_DUPE_CHECK"}).status_code == 400  # case-insensitive
    assert client.post("/api/users", headers=admin_h, json={"username": "ws6_role_bad", "role": "Root"}).status_code == 400
    assert client.post("/api/users", headers=admin_h, json={"username": "ws6_role_bad", "role": "AI Agent"}).status_code == 400
    for body in ({"expires_in_days": 0}, {"expires_in_days": 99999}, {"ip_allowlist": ["not-an-ip"]}, {"ip_allowlist": ["10.0.0.0/99"]},
                 {"ip_allowlist": ["1.1.1.1"] * 60}):
        res = client.post("/api/users/service-accounts", headers=admin_h, json={"username": "ws6-agent-bad", **body})
        assert res.status_code in (400, 422), body
    assert client.post("/api/auth/login", json={"username": "u" * 5000, "password": "x"}).status_code == 422


# --- audit trail ------------------------------------------------------------------------------------------
def test_logs_are_append_only_for_everyone(client, admin_h, db):
    from backend.models import SystemLog

    before = db.query(SystemLog).count()
    for method, body in (("post", {"source": "EDR", "message": "forged"}), ("delete", None), ("put", {}), ("patch", {})):
        res = getattr(client, method)("/api/logs", headers=admin_h, **({"json": body} if body is not None else {}))
        assert res.status_code == 405, method
    assert client.delete("/api/logs/1", headers=admin_h).status_code in (404, 405)
    assert db.query(SystemLog).count() >= before


def test_retention_purge_is_age_based_and_audited(db):
    from backend.models import SystemLog
    from backend.routers.logs import MIN_RETENTION_DAYS, purge_expired_logs, record_log

    old = record_log(db, "TEST", "INFO", "ws6 ancient entry", created_at=_naive_now() - timedelta(days=400))
    young = record_log(db, "TEST", "INFO", "ws6 recent entry", created_at=_naive_now() - timedelta(days=2))
    old_id, young_id = old.log_id, young.log_id

    with pytest.raises(ValueError):
        purge_expired_logs(db, retention_days=MIN_RETENTION_DAYS - 1)
    assert db.query(SystemLog).filter_by(log_id=old_id).first() is not None  # refused, nothing deleted

    deleted = purge_expired_logs(db, retention_days=365, actor="ws6-test-job")
    assert deleted >= 1
    assert db.query(SystemLog).filter_by(log_id=old_id).first() is None
    assert db.query(SystemLog).filter_by(log_id=young_id).first() is not None
    audit = db.query(SystemLog).filter(SystemLog.source == "AUDIT", SystemLog.target == "ws6-test-job").order_by(SystemLog.log_id.desc()).first()
    assert audit and audit.details["deleted"] == deleted and audit.details["retention_days"] == 365
    db.query(SystemLog).filter_by(log_id=young_id).delete()
    db.commit()


def test_alert_purge_needs_a_one_time_confirmation_bound_to_the_session(client, admin_h, db):
    from backend.models import SystemLog
    from backend.security_models import RevokedToken  # noqa: F401

    assert client.delete("/api/alerts/purge", headers=admin_h).status_code == 428
    assert client.delete("/api/alerts/purge", headers={**admin_h, "X-Confirm-Token": "garbage"}).status_code == 428
    make_user(client, admin_h, "ws6_purge_analyst")
    assert client.get("/api/alerts/purge/confirm", headers=bearer("ws6_purge_analyst")).status_code == 403

    # A confirmation issued to one session is useless in another session, even of the same admin.
    other_session = bearer(admin_name())
    token = client.get("/api/alerts/purge/confirm", headers=admin_h).json()["confirm_token"]
    assert client.delete("/api/alerts/purge", headers={**other_session, "X-Confirm-Token": token}).status_code == 428
    # A confirmation token is not a session token.
    assert client.get("/api/alerts", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    # Expired confirmation.
    from backend.security import issue_confirmation_token
    from backend.security import decode_access_token
    session_jti = decode_access_token(admin_h["Authorization"].split()[1])["jti"]
    stale = issue_confirmation_token("alerts_purge", admin_name(), session_jti, ttl_seconds=-5)
    assert client.delete("/api/alerts/purge", headers={**admin_h, "X-Confirm-Token": stale}).status_code == 428

    ok = client.delete("/api/alerts/purge", headers={**admin_h, "X-Confirm-Token": token})
    assert ok.status_code == 200, ok.text
    assert client.delete("/api/alerts/purge", headers={**admin_h, "X-Confirm-Token": token}).status_code == 428  # single use
    phases = [e.details.get("phase") for e in db.query(SystemLog).filter(SystemLog.source == "RBAC").all() if e.details and e.details.get("phase")]
    assert "start" in phases and "done" in phases  # audit entry before and after


def test_auditor_sees_masked_raw_payload(client, admin_h):
    secret_payload = {
        "rule": {"id": "99777", "level": 3, "description": "ws6 masking"},
        "agent": {"id": "001", "name": "ws6-host"},
        "data": {"password": "hunter2-secret", "srcuser": "jane.doe@corp.example", "api_key": "AKIAABCDEFGHIJKLMNOP"},
        "full_log": "login failed password=SuperSecret99 token=abcd1234efgh for jane.doe@corp.example Authorization: Bearer abcdefghijkl123",
    }
    token = create_token(client, admin_h, "ws6-mask-sender")["token"]
    alert_id = client.post("/api/webhooks/wazuh", json=secret_payload, headers=hook_headers(token)).json()["alert_id"]

    make_user(client, admin_h, "ws6_auditor", role="SOC Auditor (Read-Only)")
    make_user(client, admin_h, "ws6_mask_analyst", role="SOC Analyst")
    auditor, analyst = bearer("ws6_auditor"), bearer("ws6_mask_analyst")

    masked = client.get(f"/api/alerts/{alert_id}", headers=auditor)
    assert masked.status_code == 200
    payload = masked.json()["raw_payload"]
    text = json.dumps(payload)
    for leaked in ("hunter2-secret", "SuperSecret99", "abcd1234efgh", "jane.doe@", "AKIAABCDEFGHIJKLMNOP", "abcdefghijkl123"):
        assert leaked not in text, leaked
    assert payload["data"]["password"] == "[REDACTED]" and "***@corp.example" in payload["data"]["srcuser"]
    assert payload["rule"]["description"] == "ws6 masking" and payload["agent"]["name"] == "ws6-host"  # useful context kept

    full = client.get(f"/api/alerts/{alert_id}", headers=analyst).json()["raw_payload"]
    assert full["data"]["password"] == "hunter2-secret" and "jane.doe@corp.example" in full["full_log"]
    listing = client.get("/api/alerts?limit=200", headers=auditor).json()
    row = next(a for a in listing if a["alert_id"] == alert_id)
    assert "hunter2-secret" not in json.dumps(row["raw_payload"]) and "jane.doe@corp.example" not in json.dumps(row["raw_payload"])


def test_mask_sensitive_unit():
    from backend.security import mask_sensitive

    data = {"user": "bob@example.org", "nested": [{"secret": "s", "ok": 1, "note": "pwd: abc123 and passphrase=xyz"}],
            "k": "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "n": None, "t": ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"]}
    masked = mask_sensitive(data)
    assert masked["user"] == "b***@example.org" and masked["nested"][0]["secret"] == "[REDACTED]" and masked["nested"][0]["ok"] == 1
    assert "abc123" not in masked["nested"][0]["note"] and "xyz" not in masked["nested"][0]["note"]
    assert "MIIabc" not in masked["k"] and masked["n"] is None and masked["t"] == ["[REDACTED]"]
    assert data["user"] == "bob@example.org"  # input is not modified


# --- TOTP replay, MFA policy ---------------------------------------------------------------------------------
def test_totp_codes_are_single_use_and_secret_is_encrypted(client, admin_h, db, monkeypatch):
    from backend.models import User
    from backend.security import consume_totp_code

    created = make_user(client, admin_h, "ws6_totp_user")
    db.expire_all()
    h = bearer("ws6_totp_user")
    fixed = int(time.time() // 30) * 30 + 15  # pin the server clock mid-step so the +/-30s codes stay valid
    monkeypatch.setattr("backend.security.time", types.SimpleNamespace(time=lambda: fixed))

    secret = client.post("/api/auth/mfa/setup", headers=h).json()["secret"]
    db.expire_all()
    stored = db.query(User).filter_by(username="ws6_totp_user").first().mfa_secret
    assert stored.startswith("enc:v1:") and secret not in stored  # TOTP seed encrypted at rest
    totp = pyotp.TOTP(secret)

    assert client.post("/api/auth/mfa/verify", json={"code": totp.at(fixed)}, headers=h).status_code == 200
    login = {"username": "ws6_totp_user", "password": created["temporary_password"]}
    assert client.post("/api/auth/login", json={**login, "mfa_code": totp.at(fixed)}).status_code == 401  # enrolment code reused
    assert client.post("/api/auth/login", json={**login, "mfa_code": totp.at(fixed + 30)}).status_code == 200
    assert client.post("/api/auth/login", json={**login, "mfa_code": totp.at(fixed + 30)}).status_code == 401  # replay of a used code

    # Disabling needs the password AND an unused code.
    assert client.post("/api/auth/mfa/disable", headers=h, json={"code": totp.at(fixed - 30)}).status_code == 400
    assert client.post("/api/auth/mfa/disable", headers=h, json={"password": "wrong-password-123", "code": totp.at(fixed - 30)}).status_code == 400
    assert client.post("/api/auth/mfa/disable", headers=h, json={"password": created["temporary_password"], "code": totp.at(fixed + 30)}).status_code == 400  # replay
    res = client.post("/api/auth/mfa/disable", headers=h, json={"password": created["temporary_password"], "code": totp.at(fixed - 30)})
    assert res.status_code == 200 and res.json()["mfa_enabled"] is False
    db.expire_all()
    assert db.query(User).filter_by(username="ws6_totp_user").first().mfa_secret is None

    # Unit level: replay is tracked per subject.
    assert consume_totp_code(db, "ws6-subject-1", secret, totp.at(fixed)) is True
    assert consume_totp_code(db, "ws6-subject-1", secret, totp.at(fixed)) is False
    assert consume_totp_code(db, "ws6-subject-2", secret, totp.at(fixed)) is True
    assert consume_totp_code(db, "ws6-subject-1", secret, "000000") is False
    assert consume_totp_code(db, "ws6-subject-1", secret, "") is False


def test_change_password_with_mfa_needs_a_code(client, admin_h, db, monkeypatch):
    created = make_user(client, admin_h, "ws6_chpw_mfa")
    first = client.post("/api/auth/login", json={"username": "ws6_chpw_mfa", "password": created["temporary_password"]})
    done = client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {first.json()['access_token']}"},
                       json={"new_password": STRONG_PASSWORD})
    h = {"Authorization": f"Bearer {done.json()['access_token']}"}
    fixed = int(time.time() // 30) * 30 + 15
    monkeypatch.setattr("backend.security.time", types.SimpleNamespace(time=lambda: fixed))
    totp = pyotp.TOTP(client.post("/api/auth/mfa/setup", headers=h).json()["secret"])
    assert client.post("/api/auth/mfa/verify", json={"code": totp.at(fixed)}, headers=h).status_code == 200
    body = {"current_password": STRONG_PASSWORD, "new_password": "Yet-Another-Strong-Passphrase-5"}
    assert client.post("/api/auth/change-password", headers=h, json=body).status_code == 400  # no code
    assert client.post("/api/auth/change-password", headers=h, json={**body, "mfa_code": totp.at(fixed)}).status_code == 400  # used code
    assert client.post("/api/auth/change-password", headers=h, json={**body, "mfa_code": totp.at(fixed + 30)}).status_code == 200


def test_mfa_can_be_required_for_admins(client, admin_h, monkeypatch):
    make_user(client, admin_h, "ws6_policy_admin", role="Admin")
    make_user(client, admin_h, "ws6_policy_analyst", role="SOC Analyst")
    admin2, analyst = bearer("ws6_policy_admin"), bearer("ws6_policy_analyst")
    assert client.get("/api/alerts", headers=admin2).status_code == 200  # default: not enforced

    monkeypatch.setenv("PHANTOM_REQUIRE_MFA_FOR_ADMIN", "true")
    blocked = client.get("/api/alerts", headers=admin2)
    assert blocked.status_code == 403 and "Multi-factor" in blocked.json()["detail"]
    assert client.get("/api/users", headers=admin2).status_code == 403
    me = client.get("/api/auth/me", headers=admin2)
    assert me.status_code == 200 and me.json()["mfa_enrollment_required"] is True
    assert client.get("/api/alerts", headers=analyst).status_code == 200  # only administrators are affected

    setup = client.post("/api/auth/mfa/setup", headers=admin2)  # enrolment itself stays reachable
    assert setup.status_code == 200
    fixed = int(time.time() // 30) * 30 + 15
    monkeypatch.setattr("backend.security.time", types.SimpleNamespace(time=lambda: fixed))
    assert client.post("/api/auth/mfa/verify", json={"code": pyotp.TOTP(setup.json()["secret"]).at(fixed)}, headers=admin2).status_code == 200
    assert client.get("/api/alerts", headers=admin2).status_code == 200  # enrolled: access restored
