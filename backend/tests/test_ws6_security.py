"""WS6 security tests: encryption at rest, SSRF guard, rate limiting, lockout, change-password proof."""
import os

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

from backend import crypto, netguard, ratelimit
from backend.tests.ws6_helpers import (  # noqa: F401  (fixtures are used by name)
    ADMIN_PASSWORD, STRONG_PASSWORD, _clean_state, admin_h, admin_name, bearer, client_from, make_request, make_user, use_keys,
)


# --- encryption at rest ------------------------------------------------------------------
def test_encrypt_round_trip_and_legacy_plaintext_passthrough():
    token = crypto.encrypt_value("my-api-key-123")
    assert token.startswith("enc:v1:") and "my-api-key-123" not in token
    assert crypto.is_encrypted(token) and not crypto.is_encrypted("my-api-key-123")
    assert crypto.decrypt_value(token) == "my-api-key-123"
    assert crypto.decrypt_value("legacy-plaintext-row") == "legacy-plaintext-row"  # old rows keep working
    assert crypto.decrypt_value("") == "" and crypto.decrypt_value(None) is None
    assert crypto.encrypt_value(token) == token  # never double-encrypted
    assert crypto.encrypt_value("") == ""
    assert crypto.encrypt_value("my-api-key-123") != token  # fresh IV each time


def test_wrong_key_cannot_decrypt_and_production_requires_key(monkeypatch):
    key_a, key_b = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    with use_keys(single=key_a):
        token = crypto.encrypt_value("secret")
    with use_keys(single=key_b):
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt_value(token)
    monkeypatch.setenv("PHANTOM_ENV", "production")
    with use_keys():
        with pytest.raises(crypto.CryptoConfigError):
            crypto.encrypt_value("x")
    with use_keys(single="not-a-fernet-key"):
        with pytest.raises(crypto.CryptoConfigError):
            crypto.encrypt_value("x")


def test_key_rotation_with_multifernet():
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    with use_keys(single=old):
        token = crypto.encrypt_value("rotating-secret")
    with use_keys(many=f"{new},{old}"):
        assert crypto.decrypt_value(token) == "rotating-secret"  # old key still decrypts
        assert crypto.needs_rotation(token) is True
        rotated = crypto.rotate_value(token)
        assert crypto.needs_rotation(rotated) is False
    with use_keys(single=new):  # the old key can be dropped after rotation
        assert crypto.decrypt_value(rotated) == "rotating-secret"


def test_encrypt_existing_secrets_is_idempotent_and_get_setting_decrypts():
    from backend.database import SessionLocal
    from backend.integration_config import get_setting
    from backend.models import SystemConfig, User
    from backend.routers.config import ensure_default_configurations

    db = SessionLocal()
    try:
        ensure_default_configurations(db)
        row = db.query(SystemConfig).filter_by(category="TIP", key_name="threatfox_api_key").first()
        row.key_value, row.is_secret = "legacy-plain-threatfox-key", True
        db.add(User(username="ws6_mfa_legacy", password_hash="x", role="SOC Analyst", mfa_secret="JBSWY3DPEHPK3PXP"))
        db.commit()

        assert get_setting("threatfox_api_key") == "legacy-plain-threatfox-key"  # legacy plaintext still readable
        first = crypto.encrypt_existing_secrets(db)
        assert first["config"] >= 1 and first["mfa"] >= 1
        db.refresh(row)
        assert row.key_value.startswith("enc:v1:") and "legacy-plain" not in row.key_value
        legacy_user = db.query(User).filter_by(username="ws6_mfa_legacy").first()
        assert legacy_user.mfa_secret.startswith("enc:v1:")
        assert get_setting("threatfox_api_key") == "legacy-plain-threatfox-key"
        assert crypto.decrypt_value(legacy_user.mfa_secret) == "JBSWY3DPEHPK3PXP"

        again = crypto.encrypt_existing_secrets(db)
        assert again["config"] == 0 and again["mfa"] == 0  # idempotent
        db.refresh(row)
        row.key_value = ""
        db.delete(legacy_user)
        db.commit()
    finally:
        db.close()


def test_config_api_stores_secret_encrypted_and_never_returns_characters(client, admin_h):
    from backend.database import SessionLocal
    from backend.integration_config import get_setting
    from backend.models import SystemConfig

    secret = "abuse-secret-value-zz91"
    try:
        res = client.post("/api/configuration", headers=admin_h, json={"configs": [
            {"category": "TIP", "key_name": "abuseipdb_api_key", "key_value": secret}]})
        assert res.status_code == 200, res.text
        db = SessionLocal()
        try:
            raw = db.query(SystemConfig).filter_by(key_name="abuseipdb_api_key").first().key_value
        finally:
            db.close()
        assert raw.startswith("enc:v1:") and secret not in raw
        assert get_setting("abuseipdb_api_key") == secret
        body = client.get("/api/configuration", headers=admin_h)
        assert secret not in body.text and "zz91" not in body.text
        item = body.json()["TIP"]["abuseipdb_api_key"]
        assert item["is_set"] is True and item["source"] == "database" and item["value"] == ""
        # Re-saving the identical secret is recognised as unchanged (comparison happens on plaintext).
        again = client.post("/api/configuration", headers=admin_h, json={"configs": [
            {"category": "TIP", "key_name": "abuseipdb_api_key", "key_value": secret}]})
        assert "abuseipdb_api_key" in again.json()["unchanged"]
    finally:
        client.post("/api/configuration", headers=admin_h, json={"configs": [
            {"category": "TIP", "key_name": "abuseipdb_api_key", "key_value": "", "clear": True}]})


# --- SSRF guard -------------------------------------------------------------------------------
@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
    "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "224.0.0.1", "fd00:ec2::254",
])
def test_non_public_addresses_are_blocked(address):
    assert netguard.is_public_ip(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address):
    assert netguard.is_public_ip(address) is True


def test_assert_public_url_checks_scheme_credentials_and_resolution(monkeypatch):
    for bad in ("file:///etc/passwd", "ftp://example.com", "http://user:pw@example.com/", "http://127.0.0.1:8080/",
                "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://2130706433/", ""):
        with pytest.raises(netguard.UnsafeURLError):
            netguard.assert_public_url(bad)

    monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: ["93.184.216.34"])
    assert netguard.assert_public_url("https://wazuh.example.com:55000") == "https://wazuh.example.com:55000"
    # One private answer among public ones is enough to refuse (multi-record DNS tricks).
    monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: ["93.184.216.34", "10.0.0.5"])
    with pytest.raises(netguard.UnsafeURLError):
        netguard.assert_public_url("https://sneaky.example.com")


def test_guarded_backend_rechecks_at_connect_time(monkeypatch):
    """DNS rebinding: a name that was public when validated but is private when connecting is refused."""
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])
    monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: next(answers))
    netguard.assert_public_url("https://rebind.example.com")
    with pytest.raises(netguard.UnsafeURLError):
        netguard._GuardedBackend().connect_tcp("rebind.example.com", 443)


def test_guarded_client_refuses_private_targets_without_connecting():
    with netguard.guarded_client(timeout=2) as guarded:
        for url in ("http://127.0.0.1:9/", "http://169.254.169.254/latest/meta-data/", "http://10.255.255.1/"):
            with pytest.raises(netguard.UnsafeURLError):
                guarded.get(url)


def _set_wazuh(client, admin_h, url="https://wazuh.example.test:55000"):
    res = client.post("/api/configuration", headers=admin_h, json={"configs": [
        {"category": "SIEM", "key_name": "siem_manager_url", "key_value": url},
        {"category": "SIEM", "key_name": "siem_user", "key_value": "wazuh-stored-user"},
        {"category": "SIEM", "key_name": "siem_password", "key_value": "stored-wazuh-password"},
    ]})
    assert res.status_code == 200, res.text


def _clear_wazuh(client, admin_h):
    client.post("/api/configuration", headers=admin_h, json={"configs": [
        {"category": "SIEM", "key_name": k, "key_value": "", "clear": True}
        for k in ("siem_manager_url", "siem_user", "siem_password")]})


@pytest.fixture
def captured_requests(monkeypatch):
    import backend.routers.config as config_router

    seen = []
    real_client = httpx.Client

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    def factory(**kwargs):
        kwargs.pop("verify", None)
        kwargs.pop("transport", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(config_router.httpx, "Client", factory)
    return seen


def test_connection_test_uses_stored_url_and_secret_by_default(client, admin_h, captured_requests):
    _set_wazuh(client, admin_h)
    try:
        res = client.post("/api/configuration/test-connection", headers=admin_h, json={"service_name": "wazuh"})
        assert res.status_code == 200 and res.json()["status"] == "Connected"
        request = captured_requests[-1]
        assert request.url.host == "wazuh.example.test"
        assert request.headers["authorization"] == httpx.BasicAuth("wazuh-stored-user", "stored-wazuh-password")._auth_header
    finally:
        _clear_wazuh(client, admin_h)


def test_connection_test_override_ssrf_and_secret_isolation(client, admin_h, captured_requests, monkeypatch):
    _set_wazuh(client, admin_h)
    try:
        post = lambda body: client.post("/api/configuration/test-connection", headers=admin_h,
                                        json={"service_name": "wazuh", **body})
        creds = {"username": "other-user", "api_key": "other-password"}
        # Private, loopback and cloud-metadata targets are refused before any request is made.
        for target in ("http://127.0.0.1:55000", "http://169.254.169.254", "http://10.0.0.8:55000",
                       "http://[::1]:55000", "http://localhost:55000"):
            assert post({"endpoint_url": target, **creds}).status_code == 400, target
        assert captured_requests == []

        # A name that resolves to a private address is refused too (checked after DNS resolution).
        monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: ["10.9.9.9"])
        assert post({"endpoint_url": "https://internal.example.com:55000", **creds}).status_code == 400

        monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: ["93.184.216.34"])
        # A different public host without its own credentials: stored secrets are never reused for it.
        assert post({"endpoint_url": "https://attacker.example.com:55000"}).status_code == 400
        assert post({"endpoint_url": "https://attacker.example.com:55000", "username": "only-user"}).status_code == 400
        assert captured_requests == []

        # Different public host with its own credentials: only those credentials go there.
        ok = post({"endpoint_url": "https://other-wazuh.example.com:55000", **creds})
        assert ok.status_code == 200 and ok.json()["status"] == "Connected"
        sent = captured_requests[-1]
        assert sent.url.host == "other-wazuh.example.com"
        assert sent.headers["authorization"] == httpx.BasicAuth("other-user", "other-password")._auth_header
        assert "stored-wazuh-password" not in str(sent.headers)

        # Same host as the stored URL: the stored URL and stored username are used with the override key.
        same = post({"endpoint_url": "https://WAZUH.example.test:55000/", "api_key": "typed-password"})
        assert same.status_code == 200
        assert captured_requests[-1].url.host == "wazuh.example.test"
        assert captured_requests[-1].headers["authorization"] == httpx.BasicAuth("wazuh-stored-user", "typed-password")._auth_header
    finally:
        _clear_wazuh(client, admin_h)


def test_connection_test_is_admin_only_and_rate_limited(client, admin_h, monkeypatch):
    make_user(client, admin_h, "ws6_sec_eng", role="Security Engineer")
    assert client.post("/api/configuration/test-connection", headers=bearer("ws6_sec_eng"),
                       json={"service_name": "virustotal"}).status_code == 403
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_TEST_CONNECTION", "2/60")
    codes = [client.post("/api/configuration/test-connection", headers=admin_h,
                         json={"service_name": "virustotal"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


# --- rate limiting --------------------------------------------------------------------------------
def test_sliding_window_limit_and_retry_after(monkeypatch):
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_MFA", "3/60")
    for _ in range(3):
        ratelimit.enforce("mfa", "subject-1")
    with pytest.raises(HTTPException) as exc:
        ratelimit.enforce("mfa", "subject-1")
    assert exc.value.status_code == 429 and int(exc.value.headers["Retry-After"]) >= 1
    ratelimit.enforce("mfa", "subject-2")  # other subjects are unaffected
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_MFA", "off")
    ratelimit.enforce("mfa", "subject-1")  # can be disabled explicitly


def test_redis_outage_falls_back_to_memory(monkeypatch):
    monkeypatch.setenv("PHANTOM_RATELIMIT_REDIS_URL", "redis://127.0.0.1:1/0")  # nothing listens there
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_MFA", "2/60")
    ratelimit.enforce("mfa", "k")
    ratelimit.enforce("mfa", "k")
    with pytest.raises(HTTPException):
        ratelimit.enforce("mfa", "k")  # still enforced in process memory


def test_login_and_change_password_endpoints_are_rate_limited(client, monkeypatch):
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_LOGIN", "3/60")
    bad = {"username": "nobody-here", "password": "whatever-password-1"}
    assert [client.post("/api/auth/login", json=bad).status_code for _ in range(4)] == [401, 401, 401, 429]
    assert client.post("/api/auth/login", json=bad).headers["retry-after"]

    monkeypatch.setenv("PHANTOM_RATE_LIMIT_CHANGE_PASSWORD", "2/60")
    body = {"current_password": "x", "new_password": "y"}
    assert [client.post("/api/auth/change-password", json=body).status_code for _ in range(3)] == [401, 401, 429]



def test_mfa_endpoints_are_rate_limited(client, admin_h, monkeypatch):
    make_user(client, admin_h, "ws6_mfa_rl")
    monkeypatch.setenv("PHANTOM_RATE_LIMIT_MFA", "2/60")  # counted per address and per user
    h = bearer("ws6_mfa_rl")
    codes = [client.post("/api/auth/mfa/disable", headers=h).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_client_ip_trusts_forwarded_for_only_from_trusted_proxies(monkeypatch):
    monkeypatch.delenv("PHANTOM_TRUSTED_PROXIES", raising=False)
    spoofed = make_request("198.51.100.9", "203.0.113.7")
    assert ratelimit.get_client_ip(spoofed) == "198.51.100.9"  # header ignored by default

    monkeypatch.setenv("PHANTOM_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.1")
    assert ratelimit.get_client_ip(make_request("198.51.100.9", "203.0.113.7")) == "198.51.100.9"  # untrusted peer
    assert ratelimit.get_client_ip(make_request("10.0.0.2", "203.0.113.7")) == "203.0.113.7"
    # The client may prepend fake hops; the right-most untrusted hop is the real one.
    assert ratelimit.get_client_ip(make_request("10.0.0.2", "1.2.3.4, 203.0.113.7, 10.0.0.9")) == "203.0.113.7"
    assert ratelimit.get_client_ip(make_request("10.0.0.2", "not-an-ip")) == "10.0.0.2"


# --- lockout ----------------------------------------------------------------------------------------
def test_lockout_is_per_username_and_address_and_reveals_nothing(client, admin_h):
    created = make_user(client, admin_h, "ws6_lock_target")
    good = {"username": "ws6_lock_target", "password": created["temporary_password"]}
    wrong = {"username": "ws6_lock_target", "password": "definitely-wrong-password"}
    attacker, legit = client_from("203.0.113.66"), client_from("198.51.100.7")

    for _ in range(5):
        assert attacker.post("/api/auth/login", json=wrong).status_code == 401
    locked = attacker.post("/api/auth/login", json=good)  # locked from this address, even with the right password
    unknown = attacker.post("/api/auth/login", json={"username": "ws6_no_such_user", "password": "abc-def-ghi-1234"})
    wrong_pw = attacker.post("/api/auth/login", json={"username": admin_name(), "password": "abc-def-ghi-1234"})
    assert locked.status_code == unknown.status_code == wrong_pw.status_code == 401
    assert locked.json() == unknown.json() == wrong_pw.json()  # unknown / locked / wrong password look identical

    # The real user, from another address, is NOT locked out by the attacker's failures.
    assert legit.post("/api/auth/login", json=good).status_code == 200


def test_attacker_cannot_lock_out_the_admin(client):
    attacker = client_from("203.0.113.77")
    for _ in range(8):
        attacker.post("/api/auth/login", json={"username": admin_name(), "password": "guess-guess-guess-1"})
    assert attacker.post("/api/auth/login", json={"username": admin_name(), "password": ADMIN_PASSWORD}).status_code == 401
    # The admin still signs in from their own address, and from the shared test address.
    assert client_from("198.51.100.10").post("/api/auth/login", json={"username": admin_name(), "password": ADMIN_PASSWORD}).status_code == 200
    assert client.post("/api/auth/login", json={"username": admin_name(), "password": ADMIN_PASSWORD}).status_code == 200


def test_username_wide_failures_only_add_delay(client, monkeypatch):
    monkeypatch.setenv("PHANTOM_LOGIN_DELAY_SECONDS", "0.25")
    assert ratelimit.username_delay(admin_name()) == 0.0
    for i in range(7):
        ratelimit.register_failure("login", admin_name(), f"203.0.113.{100 + i}")  # 7 different addresses
    delay = ratelimit.username_delay(admin_name())
    assert 0 < delay <= 3.0
    # Not a lock: a correct login from a clean address still works (sleep stubbed to keep the test fast).
    slept = []
    monkeypatch.setattr("backend.routers.auth.time.sleep", slept.append)
    ok = client_from("198.51.100.55").post("/api/auth/login", json={"username": admin_name(), "password": ADMIN_PASSWORD})
    assert ok.status_code == 200 and slept and slept[0] > 0
    # Unknown usernames get the same treatment, so the delay does not reveal which accounts exist.
    for i in range(7):
        ratelimit.register_failure("login", "ws6-ghost-account", f"203.0.113.{120 + i}")
    assert ratelimit.username_delay("ws6-ghost-account") > 0


def test_per_address_failure_limit_blocks_a_spraying_client(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "IP_MAX_FAILURES", 4)
    sprayer = client_from("203.0.113.88")
    for name in ("spray-a", "spray-b", "spray-c", "spray-d"):
        assert sprayer.post("/api/auth/login", json={"username": name, "password": "password-guess-123"}).status_code == 401
    blocked = sprayer.post("/api/auth/login", json={"username": admin_name(), "password": ADMIN_PASSWORD})
    assert blocked.status_code == 429 and "retry-after" in blocked.headers
    assert client_from("198.51.100.99").post("/api/auth/login", json={"username": admin_name(), "password": ADMIN_PASSWORD}).status_code == 200


def test_admin_unlock_clears_the_throttle(client, admin_h):
    created = make_user(client, admin_h, "ws6_unlock_target")
    good = {"username": "ws6_unlock_target", "password": created["temporary_password"]}
    attacker = client_from("203.0.113.91")
    for _ in range(5):
        attacker.post("/api/auth/login", json={**good, "password": "wrong-wrong-wrong-1"})
    assert attacker.post("/api/auth/login", json=good).status_code == 401
    assert client.post(f"/api/users/{created['user_id']}/unlock", headers=admin_h).status_code == 200
    assert attacker.post("/api/auth/login", json=good).status_code == 200


# --- change-password requires proof -------------------------------------------------------------------
def test_change_password_has_no_unauthenticated_variant(client, admin_h):
    created = make_user(client, admin_h, "ws6_chpw_anon")
    body = {"username": "ws6_chpw_anon", "current_password": created["temporary_password"], "new_password": STRONG_PASSWORD}
    assert client.post("/api/auth/change-password", json=body).status_code == 401
    # Same answer for an account that does not exist: no username oracle.
    ghost = client.post("/api/auth/change-password", json={**body, "username": "ws6_ghost"})
    assert ghost.status_code == 401 and ghost.json() == client.post("/api/auth/change-password", json=body).json()
    # The account still has its old password.
    assert client.post("/api/auth/login", json={"username": "ws6_chpw_anon", "password": created["temporary_password"]}).status_code == 200


def test_forced_first_login_change_needs_no_current_password(client, admin_h):
    created = make_user(client, admin_h, "ws6_chpw_forced")
    login = client.post("/api/auth/login", json={"username": "ws6_chpw_forced", "password": created["temporary_password"]})
    pending = {"Authorization": f"Bearer {login.json()['access_token']}"}
    # The new password must differ from the temporary one.
    same = client.post("/api/auth/change-password", headers=pending, json={"new_password": created["temporary_password"]})
    assert same.status_code == 400
    ok = client.post("/api/auth/change-password", headers=pending, json={"new_password": STRONG_PASSWORD})
    assert ok.status_code == 200, ok.text
    assert client.get("/api/auth/me", headers=pending).status_code == 401  # the forced-change session is gone
    fresh = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    assert client.get("/api/alerts", headers=fresh).status_code == 200


def test_established_session_must_prove_the_current_password(client, admin_h):
    created = make_user(client, admin_h, "ws6_chpw_proof")
    first = client.post("/api/auth/login", json={"username": "ws6_chpw_proof", "password": created["temporary_password"]})
    pending = {"Authorization": f"Bearer {first.json()['access_token']}"}
    done = client.post("/api/auth/change-password", headers=pending, json={"new_password": STRONG_PASSWORD})
    session = {"Authorization": f"Bearer {done.json()['access_token']}"}  # established session (no pwd_change claim)
    new_password = "Another-Strong-Passphrase-77"

    assert client.post("/api/auth/change-password", headers=session, json={"new_password": new_password}).status_code == 400
    assert client.post("/api/auth/change-password", headers=session,
                       json={"current_password": "wrong-current-password", "new_password": new_password}).status_code == 400
    assert client.post("/api/auth/change-password", headers=session,
                       json={"username": "someone_else", "current_password": STRONG_PASSWORD, "new_password": new_password}).status_code == 400
    weak = client.post("/api/auth/change-password", headers=session, json={"current_password": STRONG_PASSWORD, "new_password": "password123"})
    assert weak.status_code == 400
    ok = client.post("/api/auth/change-password", headers=session, json={"current_password": STRONG_PASSWORD, "new_password": new_password})
    assert ok.status_code == 200
    assert client.get("/api/auth/me", headers=session).status_code == 401  # earlier sessions are revoked


def test_wrong_current_password_attempts_are_throttled(client, admin_h):
    created = make_user(client, admin_h, "ws6_chpw_brute")
    first = client.post("/api/auth/login", json={"username": "ws6_chpw_brute", "password": created["temporary_password"]})
    done = client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {first.json()['access_token']}"},
                       json={"new_password": STRONG_PASSWORD})
    session = {"Authorization": f"Bearer {done.json()['access_token']}"}
    for _ in range(5):
        assert client.post("/api/auth/change-password", headers=session,
                           json={"current_password": "guess-guess-guess-9", "new_password": "Whatever-New-Passphrase-1"}).status_code == 400
    # After five failures the pair is blocked: even the right current password is refused (same generic error).
    blocked = client.post("/api/auth/change-password", headers=session,
                          json={"current_password": STRONG_PASSWORD, "new_password": "Whatever-New-Passphrase-1"})
    assert blocked.status_code == 400
