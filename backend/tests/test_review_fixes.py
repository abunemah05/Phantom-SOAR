"""Regression tests for defects found by the independent final review (each one reproduced before it was fixed)."""
import os
from types import SimpleNamespace

import pytest

from backend import integration_config
from backend.engine import policy
from backend.routers import auth as auth_router
from backend.routers import config as config_router


# --- defect 1: environment values must not be frozen into the database --------------------------------------

def test_first_boot_seeds_nothing_so_environment_changes_apply_later(monkeypatch):
    assert config_router._seed_value("simulation_mode") == ""
    assert config_router._seed_value("hotl_enabled") == ""
    monkeypatch.setattr(integration_config, "_read_db_value", lambda *a, **k: "")
    monkeypatch.setenv("PHANTOM_SIMULATION_MODE", "false")
    assert integration_config.get_setting("simulation_mode") == "false"
    monkeypatch.delenv("PHANTOM_SIMULATION_MODE")
    assert integration_config.get_setting("simulation_mode") == integration_config.DEFAULTS["simulation_mode"]


# --- defect 2: Windows + Python 3.12 has no os.fchmod --------------------------------------------------------

def test_bootstrap_password_file_is_written_without_fchmod(monkeypatch, tmp_path):
    target = tmp_path / "pw.txt"
    monkeypatch.setenv("PHANTOM_BOOTSTRAP_PASSWORD_FILE", str(target))
    monkeypatch.delattr(os, "fchmod", raising=False)
    path = auth_router._write_bootstrap_password("admin", "S3cret-pass-phrase-xyz")
    assert path == target and "S3cret-pass-phrase-xyz" in target.read_text()


# --- defect 3: FQDN / e-mail / DOMAIN\user entries protect the short names too ------------------------------

@pytest.mark.parametrize("value,patterns,expected", [
    ("dc01", ["dc01.corp.local"], True),
    ("DC01.corp.local", ["dc01"], True),
    ("ceo", ["ceo@corp.com"], True),
    ("svc-backup", ["CORP\\svc-backup"], True),
    ("dc02", ["dc01.corp.local"], False),
    ("anything", ["*"], True),
    ("web-1.corp.local", ["*.corp.local"], True),
    ("web-1", ["*.corp.local"], False),   # a wildcard entry is used exactly as written, never shortened to '*'
    ("alice", ["bob@corp.com"], False),
])
def test_protected_matching_works_in_both_directions(value, patterns, expected):
    assert policy._matches_pattern(value, patterns) is expected


# --- defect 4: automation may only act through the alert's own Wazuh agent ----------------------------------

class _Alert(SimpleNamespace):
    pass


def _alert():
    return _Alert(alert_id=7, raw_payload={"agent": {"id": "001", "name": "ws-01", "ip": "10.0.0.5"},
                                           "data": {"srcip": "198.51.100.9"}}, severity="High", iocs=[])


@pytest.mark.parametrize("actor", ["agent", "playbook"])
def test_automation_cannot_name_a_different_wazuh_agent(actor):
    decision = policy.evaluate_action(None, _alert(), "block_ip", "198.51.100.9",
                                      {"agent_id": "005"}, actor=actor, confidence=0.99)
    assert decision.allowed is False and "agent_id" in " ".join(decision.reasons)


def test_automation_may_name_the_alerts_own_agent_and_analysts_may_name_another():
    own = policy.evaluate_action(None, _alert(), "block_ip", "198.51.100.9", {"agent_id": "001"},
                                 actor="agent", confidence=0.99)
    assert own.allowed is True
    analyst = policy.evaluate_action(None, _alert(), "block_ip", "198.51.100.9", {"agent_id": "005"}, actor="analyst")
    assert analyst.allowed is True


# --- defect 8: HOTL from the environment is still bound by the protected-asset requirement ------------------

def test_hotl_in_environment_is_ignored_until_protected_assets_exist(monkeypatch):
    values = {"hotl_enabled": "true", "protected_hosts": "", "protected_users": "", "protected_ips": "",
              "siem_manager_url": ""}
    original = integration_config.get_setting
    monkeypatch.setattr(integration_config, "get_setting",
                        lambda k, db=None, default=None: values[k] if k in values else original(k, db=db, default=default))
    monkeypatch.setattr(integration_config, "_system_identity", lambda: (["soar-box"], ["127.0.0.0/8"]))
    integration_config.clear_auto_protect_cache()
    assert integration_config.hotl_effective() is False
    values.update({"protected_hosts": "dc01.corp.local", "protected_users": "breakglass"})
    integration_config.clear_auto_protect_cache()
    assert integration_config.hotl_effective() is True
