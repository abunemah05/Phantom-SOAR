"""WS1: safe defaults, production checks, effective protected lists and policy enforcement."""
import socket
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import integration_config as ic
from backend.database import Base
from backend.engine.policy import evaluate_action


@pytest.fixture
def cfg(monkeypatch):
    """Settings from a plain dict (then DEFAULTS); automatic system entries pinned and deterministic."""
    values = {}

    def fake_get_setting(key_name, db=None, default=None):
        value = values.get(key_name)
        if value not in (None, ""):
            return str(value).strip()
        return str(default if default is not None else ic.DEFAULTS.get(key_name, "")).strip()

    monkeypatch.setattr(ic, "get_setting", fake_get_setting)
    monkeypatch.setattr(ic, "_system_identity", lambda: (["soar-box", "localhost"], ["127.0.0.0/8", "::1", "10.5.5.5", "10.5.5.1"]))
    monkeypatch.setattr(ic, "_resolve_host", lambda name: [])
    ic.clear_auto_protect_cache()
    yield values
    ic.clear_auto_protect_cache()


def alert_for(host="ws-01", agent_id="004", **data):
    return {"alert_id": 1, "raw_payload": {"agent": {"id": agent_id, "name": host, "ip": "10.0.4.15"}, "data": data}}


# --- defaults -----------------------------------------------------------------

def test_hotl_is_off_and_simulation_on_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("PHANTOM_HOTL_ENABLED", raising=False)
    monkeypatch.delenv("PHANTOM_SIMULATION_MODE", raising=False)
    engine = create_engine(f"sqlite:///{tmp_path / 'cfg.db'}")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    try:
        assert ic.DEFAULTS["hotl_enabled"] == "false"
        assert ic.get_bool("hotl_enabled", db=session) is False
        assert ic.is_simulation_mode(db=session) is True
    finally:
        session.close()


# --- production safety ----------------------------------------------------------

def test_production_with_simulation_and_real_connector_is_an_error(cfg, monkeypatch):
    monkeypatch.setenv("PHANTOM_ENV", "production")
    cfg.update(simulation_mode="true", okta_domain="corp.okta.com", okta_api_token="tok")
    errors = ic.production_safety_errors()
    assert len(errors) == 1 and "Okta" in errors[0]


def test_production_confirmation_or_simulation_off_clears_the_error(cfg, monkeypatch):
    monkeypatch.setenv("PHANTOM_ENV", "production")
    cfg.update(simulation_mode="true", slack_webhook_url="https://hooks.slack.test/x")
    assert ic.production_safety_errors()
    cfg["simulation_confirmed_in_production"] = "true"
    assert ic.production_safety_errors() == []
    cfg.update(simulation_confirmed_in_production="false", simulation_mode="false")
    assert ic.production_safety_errors() == []


def test_production_without_real_connectors_or_outside_production_is_fine(cfg, monkeypatch):
    cfg["simulation_mode"] = "true"
    monkeypatch.setenv("PHANTOM_ENV", "production")
    assert ic.production_safety_errors() == []
    cfg["virustotal_api_key"] = "k"
    assert ic.production_safety_errors()  # a live TIP key next to lab fixtures is also contradictory
    monkeypatch.setenv("PHANTOM_ENV", "development")
    assert ic.production_safety_errors() == []


# --- HOTL enable blockers -----------------------------------------------------------

def test_hotl_blockers_when_protected_lists_are_empty(cfg):
    blockers = ic.hotl_enable_blockers()
    assert any("protected hosts or IPs" in b for b in blockers)
    assert any("protected users" in b for b in blockers)


def test_hotl_blockers_clear_with_protected_assets_or_manager(cfg):
    cfg.update(protected_hosts="dc01", protected_users="breakglass")
    assert ic.hotl_enable_blockers() == []
    cfg.update(protected_hosts="", siem_manager_url="https://wazuh.corp.example:55000")
    assert ic.hotl_enable_blockers() == []


def test_hotl_blockers_report_invalid_entries(cfg):
    cfg.update(protected_hosts="dc01", protected_users="admin", protected_ips="not-an-ip")
    assert any("protected_ips" in b and "not-an-ip" in b for b in ic.hotl_enable_blockers())


def test_validate_protected_list():
    assert ic.validate_protected_list("protected_ips", "10.0.0.1, 192.168.0.0/16, 2001:db8::/32") == []
    assert ic.validate_protected_list("protected_ips", "10.0.0.256")
    assert ic.validate_protected_list("protected_hosts", "a b")


# --- effective protected lists ------------------------------------------------------

def test_manager_host_and_ip_are_parsed_from_the_url(cfg):
    cfg["siem_manager_url"] = "https://Wazuh.Corp.Example:55000/"
    auto = ic.automatic_protected()
    assert "wazuh.corp.example" in auto["hosts"] and "soar-box" in auto["hosts"]
    ic.clear_auto_protect_cache()
    cfg["siem_manager_url"] = "https://10.9.8.7:55000"
    assert "10.9.8.7" in ic.automatic_protected()["ips"]


def test_effective_lists_merge_configured_and_automatic_entries(cfg):
    cfg.update(protected_hosts="dc01", protected_ips="203.0.113.0/24", protected_users="Admin")
    effective = ic.effective_protected()
    assert {"dc01", "soar-box", "localhost"} <= set(effective["hosts"])
    assert {"203.0.113.0/24", "10.5.5.5", "127.0.0.0/8"} <= set(effective["ips"])
    assert effective["users"] == ["Admin"]


def test_default_gateway_parsing_and_failure(tmp_path):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n"
        "eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
    )
    assert ic._default_gateway(str(route)) == "192.168.2.1"
    assert ic._default_gateway(str(tmp_path / "missing")) is None


def test_system_identity_never_raises(monkeypatch):
    def boom(*a, **k):
        raise OSError("no network")

    monkeypatch.setattr(socket, "gethostname", boom)
    monkeypatch.setattr(socket, "getfqdn", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    hosts, ips = ic._system_identity()
    assert "localhost" in hosts and "127.0.0.0/8" in ips


# --- policy ----------------------------------------------------------------------------

@pytest.mark.parametrize("actor", ["playbook", "agent", "analyst"])
def test_wazuh_manager_ip_is_never_blocked_by_anyone(cfg, actor):
    cfg["siem_manager_url"] = "https://10.9.8.7:55000"
    decision = evaluate_action(None, alert_for(srcip="10.9.8.7"), "block_ip", "10.9.8.7", actor=actor)
    assert decision.allowed is False
    assert "never blocked" in decision.reasons[0]


@pytest.mark.parametrize("actor", ["playbook", "analyst"])
def test_this_server_cannot_be_isolated_or_blocked_even_by_an_analyst(cfg, actor):
    for ip in ("10.5.5.5", "10.5.5.1"):  # own address and the gateway
        assert evaluate_action(None, alert_for(), "block_ip", ip, actor=actor).allowed is False
    isolate = evaluate_action(None, alert_for(), "isolate_endpoint", "SOAR-BOX", actor=actor)  # case-insensitive
    assert isolate.allowed is False and "never blocked" in isolate.reasons[0]


def test_wazuh_manager_hostname_is_protected_case_insensitively(cfg):
    cfg["siem_manager_url"] = "https://Wazuh.Corp.Example:55000"
    decision = evaluate_action(None, alert_for(), "isolate_endpoint", "WAZUH.corp.example", actor="analyst")
    assert decision.allowed is False


def test_manager_agent_000_is_never_isolated_and_automation_cannot_touch_it(cfg):
    assert evaluate_action(None, alert_for(host="mgr", agent_id="000"), "isolate_endpoint", "mgr", actor="analyst").allowed is False
    terminate = evaluate_action(None, alert_for(host="mgr", agent_id="000", process="x.exe"), "terminate_process", "x.exe", actor="playbook")
    assert terminate.allowed is False and "protected" in terminate.reasons[0]


def test_protected_ips_are_cidr_aware_and_case_insensitive(cfg):
    cfg["protected_ips"] = "203.0.113.0/24, 2001:DB8::/32"
    for ip in ("203.0.113.77", "2001:db8::1", "::ffff:203.0.113.9"):
        denied = evaluate_action(None, alert_for(), "block_ip", ip, actor="playbook")
        assert denied.allowed is False, ip
        assert "protected IPs" in denied.reasons[0]
    outside = evaluate_action(None, alert_for(), "block_ip", "198.51.100.9", actor="playbook")
    assert outside.allowed is True
    analyst = evaluate_action(None, alert_for(), "block_ip", "203.0.113.77", actor="analyst")
    assert analyst.allowed is True and any("protected IPs" in r for r in analyst.reasons)


def test_protected_hosts_and_users_match_case_insensitively_and_by_short_name(cfg):
    cfg.update(protected_hosts="DC01, FILE-*", protected_users="Administrator, breakglass")
    assert evaluate_action(None, alert_for(), "isolate_endpoint", "dc01.corp.local", actor="playbook").allowed is False
    assert evaluate_action(None, alert_for(), "isolate_endpoint", "file-srv2", actor="playbook").allowed is False
    assert evaluate_action(None, alert_for(), "isolate_endpoint", "ws-77", actor="playbook").allowed is True
    for user in ("ADMINISTRATOR", "CORP\\administrator", "BreakGlass@corp.example"):
        assert evaluate_action(None, alert_for(), "disable_account", user, actor="playbook").allowed is False, user


def test_protected_host_entry_given_as_ip_protects_the_host_target(cfg):
    cfg["protected_ips"] = "10.20.0.0/16"
    assert evaluate_action(None, alert_for(), "isolate_endpoint", "10.20.3.4", actor="playbook").allowed is False
