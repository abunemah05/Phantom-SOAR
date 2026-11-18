"""AI settings: registry, validation, write-only key, runtime status, connection test (all HTTP mocked)."""
import json

import httpx
import pytest

from backend import integration_config
from backend.models import SystemConfig
from backend.routers import config as config_router
from backend.tests.ai_helpers import FAKE_KEY, db  # noqa: F401
from backend.tests.ws6_helpers import _clean_state, admin_h, bearer, make_user  # noqa: F401

AI_KEYS = {
    "openrouter_api_key": "OPENROUTER_API_KEY",
    "openrouter_model": "OPENROUTER_MODEL",
    "ai_enabled": "PHANTOM_AI_ENABLED",
    "ai_auto_triage": "PHANTOM_AI_AUTO_TRIAGE",
    "ai_max_alerts_per_minute": "PHANTOM_AI_MAX_ALERTS_PER_MINUTE",
    "ai_send_raw_payload": "PHANTOM_AI_SEND_RAW_PAYLOAD",
}


def save(client, headers, **values):
    return client.post("/api/configuration", headers=headers, json={"configs": [
        {"category": "AI", "key_name": k, "key_value": v, "clear": v == ""} for k, v in values.items()]})


@pytest.fixture(autouse=True)
def _reset_ai_settings(client, admin_h):
    yield
    save(client, admin_h, **{k: "" for k in AI_KEYS})


def test_registry_matches_the_contract():
    for key, env in AI_KEYS.items():
        assert integration_config.INTEGRATION_KEYS[key] == ("AI", env)
    assert "openrouter_api_key" in config_router.SECRET_KEYS
    assert not (config_router.SECRET_KEYS & (set(AI_KEYS) - {"openrouter_api_key"}))
    assert "AI" in config_router.CATEGORIES and "AI" not in config_router.REMOVED_CATEGORIES
    assert {"ai_enabled", "ai_auto_triage", "ai_send_raw_payload"} <= config_router.BOOL_KEYS
    d = integration_config.DEFAULTS
    assert (d["ai_enabled"], d["ai_auto_triage"], d["ai_send_raw_payload"], d["ai_max_alerts_per_minute"]) == (
        "false", "false", "false", "10")
    assert d["agent_autonomy"] == "recommend_only" and d["agent_min_confidence"] == "0.85"
    assert any(row["key_name"] == "openrouter_api_key" and row["is_secret"] for row in config_router.DEFAULT_CONFIGS)


def test_listing_shows_defaults_and_no_secret(client, admin_h):
    data = client.get("/api/configuration", headers=admin_h).json()["AI"]
    assert set(data) == set(AI_KEYS)
    assert data["ai_enabled"]["value"] == "false" and data["ai_max_alerts_per_minute"]["value"] == "10"
    assert data["openrouter_model"]["value"] == integration_config.DEFAULTS["openrouter_model"]
    assert data["openrouter_api_key"]["is_secret"] is True and data["openrouter_api_key"]["is_set"] is False
    assert data["ai_auto_triage"]["env_var"] == "PHANTOM_AI_AUTO_TRIAGE"


def test_key_is_write_only_encrypted_and_never_returned_or_logged(client, admin_h, db):
    assert save(client, admin_h, openrouter_api_key=FAKE_KEY).status_code == 200
    listing = client.get("/api/configuration", headers=admin_h)
    assert FAKE_KEY not in listing.text and "TESTKEY" not in listing.text
    item = listing.json()["AI"]["openrouter_api_key"]
    assert (item["value"], item["is_set"], item["source"], item["preview"]) == ("", True, "database", "••••••••")
    row = db.query(SystemConfig).filter(SystemConfig.key_name == "openrouter_api_key").one()
    assert row.is_secret and row.key_value.startswith("enc:v1:") and FAKE_KEY not in row.key_value

    # an empty value keeps it; the status endpoints report only that and where a key exists
    kept = save_raw(client, admin_h, "openrouter_api_key", "")
    assert kept.status_code == 200 and "openrouter_api_key" in kept.json()["unchanged"]
    status = client.get("/api/agent/status", headers=admin_h)
    assert status.json()["configured"] is True and status.json()["key_source"] == "database" and FAKE_KEY not in status.text
    runtime = client.get("/api/configuration/runtime-status", headers=admin_h)
    assert runtime.json()["integrations"]["ai"] is True and FAKE_KEY not in runtime.text
    from backend.models import SystemLog
    db.expire_all()
    logs = json.dumps([log.to_dict() for log in db.query(SystemLog).all()])
    assert FAKE_KEY not in logs and "TESTKEY" not in logs

    assert save(client, admin_h, openrouter_api_key="").status_code == 200  # clear=True
    after = client.get("/api/configuration", headers=admin_h).json()["AI"]["openrouter_api_key"]
    assert after["is_set"] is False and after["preview"] is None
    status = client.get("/api/agent/status", headers=admin_h).json()
    assert status["configured"] is False and status["key_source"] is None
    assert client.get("/api/configuration/runtime-status", headers=admin_h).json()["integrations"]["ai"] is False


def save_raw(client, headers, key, value):
    return client.post("/api/configuration", headers=headers, json={"configs": [
        {"category": "AI", "key_name": key, "key_value": value}]})


def test_environment_key_is_used_when_the_database_value_is_empty(client, admin_h, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    status = client.get("/api/agent/status", headers=admin_h)
    assert status.json()["configured"] is True and status.json()["key_source"] == "environment" and FAKE_KEY not in status.text
    assert client.get("/api/configuration/runtime-status", headers=admin_h).json()["integrations"]["ai"] is True
    assert client.get("/api/configuration", headers=admin_h).json()["AI"]["openrouter_api_key"]["source"] == "environment"


@pytest.mark.parametrize("key,value", [
    ("ai_max_alerts_per_minute", "0"), ("ai_max_alerts_per_minute", "601"), ("ai_max_alerts_per_minute", "abc"),
    ("ai_max_alerts_per_minute", "2.5"), ("ai_max_alerts_per_minute", "-1"),
    ("openrouter_model", "no spaces allowed"), ("openrouter_model", "justaname"), ("openrouter_model", "https://x.example/y"),
    ("openrouter_model", "a/b;rm -rf"), ("ai_enabled", "maybe"), ("ai_auto_triage", "2"), ("ai_send_raw_payload", "sure"),
])
def test_invalid_values_are_rejected(client, admin_h, key, value):
    res = save_raw(client, admin_h, key, value)
    assert res.status_code == 400 and key in res.json()["detail"]


def test_valid_values_are_saved_and_normalised(client, admin_h):
    res = save(client, admin_h, ai_max_alerts_per_minute="1", openrouter_model="anthropic/claude-3.5-sonnet", ai_enabled="yes",
               ai_auto_triage="on", ai_send_raw_payload="false")
    assert res.status_code == 200, res.text
    assert integration_config.get_setting("ai_max_alerts_per_minute") == "1"
    assert integration_config.get_bool("ai_enabled") and integration_config.get_bool("ai_auto_triage")
    assert integration_config.get_setting("openrouter_model") == "anthropic/claude-3.5-sonnet"
    assert save(client, admin_h, ai_max_alerts_per_minute="600").status_code == 200
    status = client.get("/api/agent/status", headers=admin_h).json()
    assert status["enabled"] and status["auto_triage"] and status["max_alerts_per_minute"] == 600
    assert status["model"] == "anthropic/claude-3.5-sonnet" and status["send_raw_payload"] is False


def test_clearing_returns_to_the_off_defaults(client, admin_h):
    save(client, admin_h, ai_enabled="true", ai_auto_triage="true")
    save(client, admin_h, ai_enabled="", ai_auto_triage="")
    status = client.get("/api/agent/status", headers=admin_h).json()
    assert status["enabled"] is False and status["auto_triage"] is False


def test_only_admins_can_change_ai_settings(client, admin_h):
    make_user(client, admin_h, "ai_settings_analyst", "SOC Analyst")
    analyst = bearer("ai_settings_analyst")
    assert save(client, analyst, ai_enabled="true").status_code == 403
    assert client.get("/api/configuration", headers=analyst).status_code == 403
    assert client.get("/api/agent/status", headers=analyst).status_code == 200  # status is for everyone signed in
    assert client.post("/api/configuration/test-connection", headers=analyst, json={"service_name": "openrouter"}).status_code == 403


# --- Connection test ---------------------------------------------------------------------------------------

@pytest.fixture
def key_endpoint(monkeypatch):
    seen = []
    state = {"status": 200, "body": {"data": {"label": "x", "usage": 1}}}
    real_client = httpx.Client

    def handler(request):
        seen.append(request)
        return httpx.Response(state["status"], json=state["body"])

    def factory(**kwargs):
        kwargs.pop("verify", None)
        kwargs.pop("transport", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(config_router.httpx, "Client", factory)
    return seen, state


def test_connection_test_not_configured_makes_no_request(client, admin_h, key_endpoint):
    seen, _ = key_endpoint
    res = client.post("/api/configuration/test-connection", headers=admin_h, json={"service_name": "OpenRouter", "category": "AI"})
    assert res.status_code == 200 and res.json()["status"] == "Not Configured" and res.json()["is_connected"] is False
    assert seen == []


def test_connection_test_connected_uses_one_read_only_call(client, admin_h, key_endpoint):
    seen, _ = key_endpoint
    assert save(client, admin_h, openrouter_api_key=FAKE_KEY).status_code == 200
    res = client.post("/api/configuration/test-connection", headers=admin_h, json={"service_name": "openrouter"})
    body = res.json()
    assert res.status_code == 200 and body["status"] == "Connected" and body["is_connected"] is True and body["category"] == "AI"
    assert FAKE_KEY not in res.text
    (request,) = seen
    assert request.method == "GET" and str(request.url) == "https://openrouter.ai/api/v1/key" and not request.content
    assert request.headers["authorization"] == f"Bearer {FAKE_KEY}"


@pytest.mark.parametrize("status,expected,needle", [(401, "Auth failed", "rejected"), (403, "Auth failed", "rejected"),
                                                    (402, "Error", "insufficient credits"), (429, "Error", "rate limiting"),
                                                    (500, "Error", "HTTP 500")])
def test_connection_test_failures(client, admin_h, key_endpoint, status, expected, needle):
    _, state = key_endpoint
    state.update(status=status, body={"error": {"code": status, "message": f"bad {FAKE_KEY}"}})
    res = client.post("/api/configuration/test-connection", headers=admin_h,
                      json={"service_name": "openrouter", "api_key": FAKE_KEY})
    body = res.json()
    assert res.status_code == 200 and body["status"] == expected and body["is_connected"] is False
    assert needle in body["message"] and body["http_status"] == status and FAKE_KEY not in res.text


def test_connection_test_unreadable_200_is_not_connected(client, admin_h, key_endpoint):
    _, state = key_endpoint
    state["body"] = {"unexpected": True}
    body = client.post("/api/configuration/test-connection", headers=admin_h,
                       json={"service_name": "openrouter", "api_key": FAKE_KEY}).json()
    assert body["status"] != "Connected" and body["is_connected"] is False


def test_connection_override_key_only_goes_to_openrouter_and_endpoint_override_is_ignored(client, admin_h, key_endpoint):
    seen, _ = key_endpoint
    res = client.post("/api/configuration/test-connection", headers=admin_h,
                      json={"service_name": "openrouter", "api_key": "sk-or-override-key-0001", "endpoint_url": "https://evil.example/steal"})
    assert res.json()["status"] == "Connected"
    assert [r.url.host for r in seen] == ["openrouter.ai"] and seen[0].headers["authorization"] == "Bearer sk-or-override-key-0001"


def test_no_alert_data_is_ever_sent_by_the_connection_test(client, admin_h, key_endpoint):
    seen, _ = key_endpoint
    client.post("/api/configuration/test-connection", headers=admin_h, json={"service_name": "openrouter", "api_key": FAKE_KEY})
    assert all(not r.content and r.method == "GET" for r in seen)
