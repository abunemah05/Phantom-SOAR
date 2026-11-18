"""Wazuh active-response client: token cache, TLS settings, request shape, retries (WS3)."""
import base64
import json
import logging

import httpx
import pytest

from backend import integration_config
from backend.integrations import connector_base, edr
from backend.integrations.edr import edr_client
from backend.integrations.firewall import firewall_client

WAZUH = {
    "siem_manager_url": "https://wazuh.test:55000",
    "siem_user": "wazuh-wui",
    "siem_password": "wazuh-secret",
}
NOW = 1_800_000_000.0


def make_jwt(exp):
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256'})}.{b64({'sub': 'wazuh-wui', 'exp': exp})}.sig"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    edr.clear_token_cache()
    monkeypatch.setattr(edr, "_now", lambda: NOW)
    monkeypatch.setattr(connector_base, "sleep", lambda s: None)
    yield
    edr.clear_token_cache()


@pytest.fixture
def settings(monkeypatch):
    overrides = dict(WAZUH)
    original = integration_config.get_setting

    def fake(key_name, db=None, default=None):
        if key_name in overrides:
            return overrides[key_name]
        return original(key_name, db=db, default=default)

    monkeypatch.setattr(integration_config, "get_setting", fake)
    return overrides


class Wazuh:
    """Fake manager: counts logins, can expire tokens, records requests and client verify args."""

    def __init__(self, monkeypatch, token_exp=NOW + 900, ar_statuses=None, affected=("004",)):
        self.requests, self.verify_args, self.logins = [], [], 0
        self.token_exp, self.affected = token_exp, list(affected)
        self.ar_statuses = list(ar_statuses or [])
        self.revoked = set()
        transport = httpx.MockTransport(self.handle)

        def factory(verify=True):
            self.verify_args.append(verify)
            return httpx.Client(transport=transport)
        monkeypatch.setattr(connector_base, "http_client", factory)

    def handle(self, request):
        self.requests.append(request)
        if request.url.path == "/security/user/authenticate":
            self.logins += 1
            return httpx.Response(200, json={"data": {"token": make_jwt(self.token_exp + self.logins)}})
        token = request.headers["authorization"].split(" ", 1)[1]
        if self.ar_statuses:
            status = self.ar_statuses.pop(0)
            if status != 200:
                return httpx.Response(status, headers={"Retry-After": "1"} if status == 503 else {}, json={})
        if token in self.revoked:
            return httpx.Response(401, json={"title": "Unauthorized"})
        return httpx.Response(200, json={"data": {"affected_items": self.affected, "failed_items": []}, "error": 0})

    @property
    def ar_requests(self):
        return [r for r in self.requests if r.url.path == "/active-response"]


# --- verified request shape -------------------------------------------------------------

def test_ar_request_shape_uses_bang_prefix_and_agents_list(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    result = edr_client.terminate_process("evil.exe", agent_id="004", pid=4242)
    assert result["status"] == "Success"
    req = fake.ar_requests[0]
    assert req.method == "PUT" and req.url.params["agents_list"] == "004"
    body = json.loads(req.content)
    assert body["command"] == "!phantom-kill-process"
    assert body["arguments"] == ["evil.exe", "4242"]
    assert set(body) == {"command", "arguments", "alert"}
    assert result["details"]["wire_commands"] == ["!phantom-kill-process"]


def test_prefix_can_be_disabled_for_ar_conf_names(settings, monkeypatch):
    settings["wazuh_ar_script_prefix"] = "false"
    settings["wazuh_ar_isolate_command"] = "phantom-isolate-host0"
    fake = Wazuh(monkeypatch)
    edr_client.isolate_endpoint("h", agent_id="004")
    assert json.loads(fake.ar_requests[0].content)["command"] == "phantom-isolate-host0"


def test_windows_agents_get_cmd_suffix_in_separate_request(settings, monkeypatch):
    settings["wazuh_windows_agent_ids"] = "007, 12"
    fake = Wazuh(monkeypatch, affected=("007",))
    result = edr_client.isolate_endpoint("win-host", agent_id="007")
    assert json.loads(fake.ar_requests[0].content)["command"] == "!phantom-isolate-host.cmd"
    assert result["status"] == "Success"
    edr_client.isolate_endpoint("lin-host", agent_id="004")
    assert json.loads(fake.ar_requests[1].content)["command"] == "!phantom-isolate-host"


def test_manager_agent_and_malformed_agent_ids_are_refused_without_calls(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    for bad in ("000", "0", "001,002", "all", "../1"):
        result = edr_client.isolate_endpoint("h", agent_id=bad)
        assert result["status"] == "Failed", bad
    assert fake.requests == []


# --- JWT cache ----------------------------------------------------------------------------

def test_token_is_cached_across_actions(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    first = edr_client.isolate_endpoint("h", agent_id="004")
    second = edr_client.unisolate_endpoint("h", agent_id="004")
    assert fake.logins == 1 and len(fake.ar_requests) == 2
    assert first["details"]["token_cached"] is False
    assert second["details"]["token_cached"] is True


def test_token_refreshed_about_a_minute_before_expiry(settings, monkeypatch):
    fake = Wazuh(monkeypatch, token_exp=NOW + 900)
    edr_client.isolate_endpoint("h", agent_id="004")
    # exp is NOW+901 for the first login; at exp-59s the cached token must still be used...
    monkeypatch.setattr(edr, "_now", lambda: NOW + 901 - 61)
    edr_client.isolate_endpoint("h", agent_id="004")
    assert fake.logins == 1
    # ...and at exp-59s it must be replaced.
    monkeypatch.setattr(edr, "_now", lambda: NOW + 901 - 59)
    edr_client.isolate_endpoint("h", agent_id="004")
    assert fake.logins == 2


def test_401_triggers_one_relogin_and_resend(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    edr_client.isolate_endpoint("h", agent_id="004")
    fake.revoked.add(make_jwt(NOW + 900 + 1))  # server-side revocation of the cached token
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert result["status"] == "Success"
    assert fake.logins == 2
    assert len(fake.ar_requests) == 3  # ok, 401, ok


def test_persistent_401_fails_after_a_single_relogin(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    fake.revoked = type("All", (), {"__contains__": lambda self, x: True})()
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert result["status"] == "Failed" and "HTTP 401" in result["error"]
    assert fake.logins == 2


def test_token_without_readable_exp_is_not_cached(settings, monkeypatch):
    calls = {"n": 0}

    def handler(request):
        if request.url.path.endswith("/authenticate"):
            calls["n"] += 1
            return httpx.Response(200, json={"data": {"token": "opaque-token"}})
        return httpx.Response(200, json={"data": {"affected_items": ["004"], "failed_items": []}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(connector_base, "http_client", lambda verify=True: httpx.Client(transport=transport))
    edr_client.isolate_endpoint("h", agent_id="004")
    edr_client.isolate_endpoint("h", agent_id="004")
    assert calls["n"] == 2
    assert edr.jwt_expiry("opaque-token") is None
    assert edr.jwt_expiry(make_jwt(123)) == 123.0


def test_token_cache_is_thread_safe(settings, monkeypatch):
    import threading
    fake = Wazuh(monkeypatch)
    threads = [threading.Thread(target=lambda: edr_client.isolate_endpoint("h", agent_id="004")) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert fake.logins == 1 and len(fake.ar_requests) == 8


def test_cache_is_keyed_by_credentials(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    edr_client.isolate_endpoint("h", agent_id="004")
    settings["siem_password"] = "another-password"
    edr_client.isolate_endpoint("h", agent_id="004")
    assert fake.logins == 2


# --- TLS ---------------------------------------------------------------------------------

def test_default_verifies_tls_and_records_it(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert fake.verify_args == [True]
    assert result["details"]["tls_verified"] is True


def test_ca_bundle_path_is_passed_as_verify(settings, monkeypatch, tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    settings["wazuh_ca_bundle"] = str(bundle)
    fake = Wazuh(monkeypatch)
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert fake.verify_args == [str(bundle)]
    assert result["details"]["tls_verified"] is True
    assert result["details"]["tls_ca_bundle"] == str(bundle)


def test_missing_ca_bundle_file_fails_without_calling(settings, monkeypatch, tmp_path):
    settings["wazuh_ca_bundle"] = str(tmp_path / "nope.pem")
    fake = Wazuh(monkeypatch)
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert result["status"] == "Failed" and "wazuh_ca_bundle" in result["error"]
    assert fake.requests == []


def test_verify_disabled_warns_loudly_and_is_reported(settings, monkeypatch, caplog):
    settings["siem_verify_tls"] = "false"
    fake = Wazuh(monkeypatch)
    with caplog.at_level(logging.WARNING):
        result = edr_client.isolate_endpoint("h", agent_id="004")
    assert fake.verify_args == [False]
    assert result["status"] == "Success"
    assert result["details"]["tls_verified"] is False
    assert any(r.levelno == logging.WARNING and "VERIFICATION IS DISABLED" in r.getMessage() for r in caplog.records)


def test_http_client_accepts_a_ca_bundle_path(tmp_path):
    import certifi
    client = connector_base.http_client(verify=certifi.where())  # a real PEM bundle path is accepted
    assert client.is_closed is False
    client.close()
    junk = tmp_path / "junk.pem"
    junk.write_text("not a certificate")
    with pytest.raises(Exception):
        connector_base.http_client(verify=str(junk))  # httpx loads the bundle eagerly


# --- retries wired into the Wazuh client ------------------------------------------------------

def test_transient_503_on_login_path_is_retried_and_counted(settings, monkeypatch):
    calls = {"auth": 0}

    def handler(request):
        if request.url.path.endswith("/authenticate"):
            calls["auth"] += 1
            if calls["auth"] == 1:
                return httpx.Response(503)
            return httpx.Response(200, json={"data": {"token": make_jwt(NOW + 900)}})
        return httpx.Response(200, json={"data": {"affected_items": ["004"], "failed_items": []}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(connector_base, "http_client", lambda verify=True: httpx.Client(transport=transport))
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert result["status"] == "Success"
    assert result["details"]["attempts"] == 3  # 2 login attempts + 1 active-response call


def test_ar_503_with_retry_after_is_retried_but_read_timeout_is_not(settings, monkeypatch):
    fake = Wazuh(monkeypatch, ar_statuses=[503, 200])
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert result["status"] == "Success" and len(fake.ar_requests) == 2

    edr.clear_token_cache()
    seen = []

    def handler(request):
        if request.url.path.endswith("/authenticate"):
            return httpx.Response(200, json={"data": {"token": make_jwt(NOW + 900)}})
        seen.append(request)
        raise httpx.ReadTimeout("slow", request=request)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(connector_base, "http_client", lambda verify=True: httpx.Client(transport=transport))
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert result["status"] == "Failed" and "Timed out" in result["error"]
    assert len(seen) == 1  # a response action is never repeated after a read timeout


def test_ar_502_without_retry_after_is_not_repeated(settings, monkeypatch):
    fake = Wazuh(monkeypatch, ar_statuses=[502, 200])
    result = edr_client.isolate_endpoint("h", agent_id="004")
    assert result["status"] == "Failed" and len(fake.ar_requests) == 1


# --- firewall arguments ------------------------------------------------------------------------

def test_block_ip_sends_ip_duration_and_direction(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    result = firewall_client.block_ip("198.51.100.45", agent_id="004", duration_hours=48, direction="both")
    body = json.loads(fake.ar_requests[0].content)
    assert body["command"] == "!phantom-block-ip"
    assert body["arguments"] == ["198.51.100.45", "48", "both"]
    assert body["alert"]["data"]["srcip"] == "198.51.100.45"
    assert result["details"]["requested"] == {"duration_hours": 48, "direction": "both"}
    assert result["details"]["honoured"] is True


def test_block_ip_defaults_to_a_bounded_inbound_block(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    firewall_client.block_ip("198.51.100.45", agent_id="004")
    assert json.loads(fake.ar_requests[0].content)["arguments"] == ["198.51.100.45", "24", "inbound"]
    settings["wazuh_default_block_hours"] = "0"
    firewall_client.block_ip("198.51.100.45", agent_id="004")
    assert json.loads(fake.ar_requests[1].content)["arguments"] == ["198.51.100.45", "0", "inbound"]


@pytest.mark.parametrize("kwargs", [
    {"duration_hours": 0}, {"duration_hours": 721}, {"duration_hours": "abc"}, {"duration_hours": True},
    {"duration_hours": 1.5}, {"direction": "sideways"},
])
def test_block_ip_rejects_invalid_parameters_without_calling(settings, monkeypatch, kwargs):
    fake = Wazuh(monkeypatch)
    result = firewall_client.block_ip("198.51.100.45", agent_id="004", **kwargs)
    assert result["status"] == "Failed" and fake.requests == []


def test_invalid_ip_is_rejected_for_all_firewall_actions(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    for call in (firewall_client.block_ip, firewall_client.unblock_ip, firewall_client.apply_rate_limit):
        assert call("1.2.3.4; rm -rf /", agent_id="004")["status"] == "Failed"
    assert fake.requests == []


def test_stock_firewall_drop_reports_that_parameters_are_not_honoured(settings, monkeypatch):
    settings["wazuh_ar_block_command"] = "firewall-drop"
    fake = Wazuh(monkeypatch)
    result = firewall_client.block_ip("198.51.100.45", agent_id="004", duration_hours=48)
    body = json.loads(fake.ar_requests[0].content)
    assert body["command"] == "!firewall-drop" and body["arguments"] == []
    assert body["alert"]["data"]["srcip"] == "198.51.100.45"
    assert result["details"]["honoured"] is False and "ignores duration" in result["details"]["note"]


def test_unblock_and_rate_limit_arguments(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    firewall_client.unblock_ip("198.51.100.45", agent_id="004")
    firewall_client.apply_rate_limit("198.51.100.45", rate="5/second", agent_id="004", duration_hours=6)
    firewall_client.apply_rate_limit("198.51.100.45", agent_id="004")
    bodies = [json.loads(r.content) for r in fake.ar_requests]
    assert bodies[0]["command"] == "!phantom-unblock-ip" and bodies[0]["arguments"] == ["198.51.100.45"]
    assert bodies[1]["command"] == "!phantom-rate-limit"
    assert bodies[1]["arguments"] == ["198.51.100.45", "5/second", "6"]
    assert bodies[2]["arguments"] == ["198.51.100.45", "10/minute", "24"]


def test_invalid_rate_is_rejected(settings, monkeypatch):
    fake = Wazuh(monkeypatch)
    for rate in ("fast", "0/second", "10/fortnight", "10/minute; drop"):
        assert firewall_client.apply_rate_limit("198.51.100.45", rate=rate, agent_id="004")["status"] == "Failed"
    assert fake.requests == []


def test_firewall_agent_ids_setting_still_overrides_agent(settings, monkeypatch):
    settings["wazuh_firewall_agent_ids"] = "010,011"
    fake = Wazuh(monkeypatch, affected=("010", "011"))
    firewall_client.block_ip("198.51.100.45", agent_id="004")
    assert fake.ar_requests[0].url.params["agents_list"] == "010,011"
