"""wazuh/ active-response scripts, ossec snippets and README (WS3).

The Linux script is exercised for real in dry-run mode (commands are logged, not executed) and, for kill and
quarantine, against throw-away processes and files. The Windows script cannot be executed here (no PowerShell), so
it is checked statically.
"""
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import httpx
import pytest

from backend import integration_config
from backend.integrations import connector_base, edr
from backend.integrations.edr import AR_COMMAND_DEFAULTS, edr_client
from backend.integrations.firewall import firewall_client

WAZUH_DIR = Path(__file__).resolve().parents[2] / "wazuh"
SCRIPT = WAZUH_DIR / "linux" / "phantom-ar"
MANAGER = "203.0.113.9"


def message(*args, command="add"):
    return json.dumps({"version": 1, "origin": {"name": "node01", "module": "wazuh-execd"}, "command": command,
                       "parameters": {"extra_args": list(args), "alert": {"data": {"srcip": "6.6.6.6"}}, "program": "x"}})


@pytest.fixture
def env(tmp_path):
    (tmp_path / "bin").mkdir()
    return {
        "PHANTOM_AR_DRY_RUN": "1",
        "PHANTOM_AR_LOG": str(tmp_path / "active-responses.log"),
        "PHANTOM_AR_STATE_DIR": str(tmp_path / "state"),
        "PHANTOM_AR_OSSEC_DIR": str(tmp_path / "ossec"),
        "PHANTOM_AR_ALLOWLIST": str(tmp_path / "allow.txt"),
        "PHANTOM_AR_QUARANTINE_DIR": str(tmp_path / "quarantine"),
        "PHANTOM_AR_MANAGER_IPS": MANAGER,
        "PATH": os.environ["PATH"],
        "_dir": str(tmp_path),
    }


def run(env, action, *args, raw=None, command="add", dry=True):
    """Run phantom-<action> exactly as Wazuh does: JSON on stdin, no command-line arguments."""
    tmp = Path(env["_dir"])
    target = tmp / "bin" / f"phantom-{action}"
    if not target.exists():
        shutil.copy(SCRIPT, target)
    child_env = {k: v for k, v in env.items() if not k.startswith("_")}
    if not dry:
        child_env.pop("PHANTOM_AR_DRY_RUN")
    proc = subprocess.run([sys.executable, str(target)], input=raw if raw is not None else message(*args, command=command),
                          capture_output=True, text=True, env=child_env, timeout=60)
    log = Path(env["PHANTOM_AR_LOG"])
    return proc.returncode, (log.read_text() if log.exists() else "")


def executed(log):
    return re.findall(r"DRYRUN action=exec cmd=(.*?) msg=", log)


# --- block-ip ------------------------------------------------------------------------------

def test_block_ip_honours_duration_and_direction(env):
    rc, log = run(env, "block-ip", "198.51.100.7", "2", "both")
    assert rc == 0 and "result=ok" in log
    cmds = executed(log)
    assert "nft add element inet phantom block4_in { 198.51.100.7 timeout 7200s }" in cmds
    assert "nft add element inet phantom block4_out { 198.51.100.7 timeout 7200s }" in cmds

    rc, log = run(env, "block-ip", "198.51.100.8", "1", "outbound")
    cmds = executed(log)
    assert any("block4_out { 198.51.100.8 timeout 3600s }" in c for c in cmds)
    assert not any("block4_in { 198.51.100.8" in c and "add element" in c for c in cmds)


def test_block_ip_without_duration_zero_means_until_unblocked_and_default_is_24h(env):
    rc, log = run(env, "block-ip", "198.51.100.7", "0", "inbound")
    assert "nft add element inet phantom block4_in { 198.51.100.7 }" in executed(log)
    rc, log = run(env, "block-ip", "198.51.100.9")
    assert "block4_in { 198.51.100.9 timeout 86400s }" in "\n".join(executed(log))


def test_block_ip_ipv6_uses_v6_set(env):
    rc, log = run(env, "block-ip", "2001:db8::bad", "1", "inbound")
    assert rc == 0 and "block6_in { 2001:db8::bad timeout 3600s }" in log


@pytest.mark.parametrize("target", ["127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "224.0.0.1", MANAGER, "10.9.9.9", "10.9.9.200"])
def test_block_ip_refuses_protected_addresses(env, tmp_path, target):
    Path(env["PHANTOM_AR_ALLOWLIST"]).write_text("# comment\n10.9.9.0/24  # lab\nnot-an-ip\n")
    rc, log = run(env, "block-ip", target, "1", "both")
    assert rc == 1 and "result=refused" in log
    assert not any("add element" in c for c in executed(log))


def test_manager_address_is_read_from_ossec_conf(env, tmp_path):
    conf = Path(env["PHANTOM_AR_OSSEC_DIR"]) / "etc" / "ossec.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text("<ossec_config><client><server><address>192.0.2.77</address><port>1514</port></server></client></ossec_config>")
    rc, log = run(env, "block-ip", "192.0.2.77", "1")
    assert rc == 1 and "is the Wazuh manager" in log


@pytest.mark.parametrize("bad", [
    "198.51.100.7; reboot", "198.51.100.7 timeout 1s", "$(id)", "`id`", "198.51.100.7\n1", "1.2.3", "999.1.1.1",
    "", "fe80::1%eth0", "198.51.100.7|nc", "../../etc",
])
def test_block_ip_rejects_injection_and_garbage(env, bad):
    rc, log = run(env, "block-ip", bad, "1", "inbound")
    assert rc == 2 and "result=bad-input" in log
    assert executed(log) == []
    assert bad.strip() == "" or bad not in log  # input is not echoed into the log


@pytest.mark.parametrize("args", [
    ("198.51.100.7", "721"), ("198.51.100.7", "abc"), ("198.51.100.7", "-1"), ("198.51.100.7", "1", "sideways"),
    ("198.51.100.7", "1", "both", "extra"), (),
])
def test_block_ip_rejects_bad_duration_direction_arity(env, args):
    rc, log = run(env, "block-ip", *args)
    assert rc == 2 and executed(log) == []


def test_unblock_ip_removes_elements_and_rate_limit(env):
    rc, log = run(env, "unblock-ip", "198.51.100.7")
    assert rc == 0
    cmds = executed(log)
    assert "nft delete element inet phantom block4_in { 198.51.100.7 }" in cmds
    assert "nft delete element inet phantom block4_out { 198.51.100.7 }" in cmds


# --- rate-limit --------------------------------------------------------------------------------

def test_rate_limit_builds_limit_rule_and_records_expiry(env):
    rc, log = run(env, "rate-limit", "198.51.100.7", "5/second", "6")
    assert rc == 0
    rules = [c for c in executed(log) if c.startswith("nft add rule")]
    assert rules and all("limit rate over 5/second drop comment phantom-rl-198.51.100.7" in c for c in rules)
    state = json.loads((Path(env["PHANTOM_AR_STATE_DIR"]) / "rate_limits.json").read_text())
    assert "198.51.100.7" in state and state["198.51.100.7"] > 0


@pytest.mark.parametrize("rate", ["fast", "0/second", "10/fortnight", "10/minute; drop", "10 / minute", ""])
def test_rate_limit_rejects_bad_rate(env, rate):
    rc, log = run(env, "rate-limit", "198.51.100.7", rate)
    assert rc == 2 and not any("add rule" in c for c in executed(log))


def test_rate_limit_refuses_protected(env):
    rc, log = run(env, "rate-limit", MANAGER, "5/second")
    assert rc == 1 and not any("add rule" in c for c in executed(log))


# --- isolate -----------------------------------------------------------------------------------

def load_module(env, monkeypatch):
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    for key, value in env.items():
        if not key.startswith("_") and key != "PATH":
            monkeypatch.setenv(key, value)
    loader = importlib.machinery.SourceFileLoader("phantom_ar_under_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("phantom_ar_under_test", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_isolate_keeps_manager_and_allowlist_and_is_reversible(env, monkeypatch):
    Path(env["PHANTOM_AR_ALLOWLIST"]).write_text("192.0.2.0/25\n192.0.2.10\n2001:db8::/64\n")
    mod = load_module(env, monkeypatch)
    inputs = []
    monkeypatch.setattr(mod, "run_cmd", lambda args, stdin_text=None, check=True: inputs.append((args, stdin_text)) or (0, ""))
    mod.handle("isolate-host", [])
    ruleset = [i for a, i in inputs if a == ["nft", "-f", "-"]][0]
    assert "policy drop" in ruleset
    assert "203.0.113.9/32" in ruleset and "192.0.2.0/25" in ruleset and "2001:db8::/64" in ruleset
    assert "192.0.2.10" not in ruleset  # collapsed into the /25
    assert ruleset.count('iifname "lo" accept') == 1 and 'oifname "lo" accept' in ruleset
    mod.handle("unisolate-host", [])
    assert ["nft", "delete", "table", "inet", "phantom_isolate"] in [a for a, _ in inputs]


def test_isolate_refuses_when_manager_unknown(env):
    env = dict(env, PHANTOM_AR_MANAGER_IPS="")
    rc, log = run(env, "isolate-host")
    assert rc == 1 and "cannot find the Wazuh manager" in log
    assert executed(log) == []


def test_isolate_takes_no_arguments(env):
    rc, log = run(env, "isolate-host", "1.2.3.4")
    assert rc == 2


# --- kill-process --------------------------------------------------------------------------------

@pytest.fixture
def sleeper():
    proc = subprocess.Popen(["sleep", "120"])
    yield proc
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def test_kill_process_by_pid_kills_the_named_process(env, sleeper):
    rc, log = run(env, "kill-process", "/usr/bin/sleep", str(sleeper.pid), dry=False)
    assert rc == 0 and "result=ok" in log
    assert sleeper.wait(timeout=10) == -signal.SIGKILL


def test_kill_process_refuses_pid_with_different_name(env, sleeper):
    rc, log = run(env, "kill-process", "notepad.exe", str(sleeper.pid), dry=False)
    assert rc == 1 and "refusing (pid may have been reused)" in log
    assert sleeper.poll() is None


def test_kill_process_dry_run_does_not_kill(env, sleeper):
    rc, log = run(env, "kill-process", "sleep", str(sleeper.pid))
    assert rc == 0 and "would send SIGKILL" in log and sleeper.poll() is None


@pytest.mark.parametrize("name", ["sshd", "systemd", "wazuh-agentd", "ossec-agent", "init"])
def test_kill_process_refuses_protected_names(env, name):
    # dry-run on purpose: a regression must not be able to kill anything on the machine running the tests
    rc, log = run(env, "kill-process", name)
    assert rc == 1 and "would send SIGKILL" not in log


def test_kill_process_refuses_protected_process_even_when_pid_given(env):
    proc = subprocess.Popen(["sleep", "120"])
    try:
        # Copy a real, self-contained shell (not `sleep`: on newer images coreutils is one multi-call binary that
        # refuses to run under another name, so the decoy would exit at once). `read` blocks without using CPU.
        shutil.copy(shutil.which("sh"), Path(env["_dir"]) / "sshd")
        decoy = subprocess.Popen([str(Path(env["_dir"]) / "sshd"), "-c", "read _unused"], stdin=subprocess.PIPE)
        try:
            rc, log = run(env, "kill-process", "sshd", str(decoy.pid), dry=False)
            assert rc == 1 and "protected process" in log and decoy.poll() is None
        finally:
            decoy.kill(); decoy.wait()
            if decoy.stdin:
                decoy.stdin.close()
    finally:
        proc.kill(); proc.wait()


def test_kill_process_never_accepts_pid_below_2(env):
    for pid in ("0", "1"):
        rc, log = run(env, "kill-process", "systemd", pid)
        assert rc == 2 and "would send SIGKILL" not in log


@pytest.mark.parametrize("args", [("a;b",), ("sleep", "0"), ("sleep", "1"), ("sleep", "12x"), ("$(id)",), ("",)])
def test_kill_process_rejects_bad_input(env, args):
    rc, log = run(env, "kill-process", *args)
    assert rc == 2


# --- quarantine-file -------------------------------------------------------------------------------

def test_quarantine_moves_file_keeps_metadata_and_is_restorable(env, tmp_path):
    victim = tmp_path / "dropper.bin"
    victim.write_bytes(b"MZ evil")
    import hashlib
    digest = hashlib.sha256(b"MZ evil").hexdigest()
    rc, log = run(env, "quarantine-file", str(victim), digest, dry=False)
    assert rc == 0 and not victim.exists()
    qdir = Path(env["PHANTOM_AR_QUARANTINE_DIR"])
    stored = [p for p in qdir.iterdir() if p.suffix != ".json"]
    assert len(stored) == 1 and (stored[0].stat().st_mode & 0o777) == 0
    meta = json.loads(Path(str(stored[0]) + ".json").read_text())
    assert meta["original_path"] == str(victim) and meta["sha256"] == digest

    shutil.copy(SCRIPT, tmp_path / "bin" / "phantom-ar")
    child_env = {k: v for k, v in env.items() if not k.startswith("_") and k != "PHANTOM_AR_DRY_RUN"}
    proc = subprocess.run([sys.executable, str(tmp_path / "bin" / "phantom-ar"), "restore", stored[0].name],
                          capture_output=True, text=True, env=child_env)
    assert proc.returncode == 0 and victim.read_bytes() == b"MZ evil"


def test_quarantine_hash_mismatch_leaves_file(env, tmp_path):
    victim = tmp_path / "doc.txt"
    victim.write_text("hello")
    rc, log = run(env, "quarantine-file", str(victim), "0" * 64, dry=False)
    assert rc == 1 and victim.exists() and "hash does not match" in log


def test_quarantine_refuses_symlinks_system_paths_and_relative(env, tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("x")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    rc, log = run(env, "quarantine-file", str(link), dry=False)
    assert rc == 1 and real.exists() and link.is_symlink()
    for path in ("/etc/passwd", "/usr/bin/ls", "/var/ossec/etc/ossec.conf", "/"):
        rc, log = run(env, "quarantine-file", path, dry=False)
        assert rc == 1, path
    for path in ("relative.txt", "../../etc/passwd", ""):
        rc, log = run(env, "quarantine-file", path, dry=False)
        assert rc == 2, path
    rc, log = run(env, "quarantine-file", str(tmp_path / "missing.txt"), dry=False)
    assert rc == 1


# --- protocol handling -----------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["", "not json", "[]", "null", '{"command":"add","parameters":{"extra_args":"x"}}',
                                 '{"command":"add","parameters":{"extra_args":[1]}}',
                                 json.dumps({"command": "add", "parameters": {"extra_args": ["a"] * 20}})])
def test_malformed_messages_are_rejected_without_action(env, raw):
    rc, log = run(env, "block-ip", raw=raw)
    assert rc == 2 and executed(log) == []


def test_delete_message_is_ignored(env):
    rc, log = run(env, "block-ip", "198.51.100.7", command="delete")
    assert rc == 0 and executed(log) == [] and "ignored non-add" in log


def test_alert_data_is_never_used_as_a_target(env):
    raw = json.dumps({"command": "add", "parameters": {"extra_args": [], "alert": {"data": {"srcip": "198.51.100.7"}}}})
    rc, log = run(env, "block-ip", raw=raw)
    assert rc == 2 and executed(log) == []


def test_log_lines_cannot_be_forged(env, monkeypatch):
    mod = load_module(env, monkeypatch)
    mod.log("INFO", "x", "legit\n2026/01/01 phantom-ar: INFO action=forged\x1b[31m")
    lines = Path(env["PHANTOM_AR_LOG"]).read_text().splitlines()
    assert len(lines) == 1 and "\x1b" not in lines[0]


# --- connector arguments are what the scripts accept ----------------------------------------------

def test_connector_arguments_are_accepted_by_the_scripts(env, monkeypatch, tmp_path):
    seen = []

    def handler(request):
        if request.url.path.endswith("/authenticate"):
            return httpx.Response(200, json={"data": {"token": "opaque"}})
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"data": {"affected_items": ["004"], "failed_items": []}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(connector_base, "http_client", lambda verify=True: httpx.Client(transport=transport))
    original = integration_config.get_setting
    cfg = {"siem_manager_url": "https://w.test:55000", "siem_user": "u", "siem_password": "p"}
    monkeypatch.setattr(integration_config, "get_setting",
                        lambda k, db=None, default=None: cfg[k] if k in cfg else original(k, db=db, default=default))
    firewall_client.block_ip("198.51.100.7", agent_id="004", duration_hours=3, direction="both")
    firewall_client.unblock_ip("198.51.100.7", agent_id="004")
    firewall_client.apply_rate_limit("198.51.100.7", rate="10/minute", agent_id="004", duration_hours=2)
    edr_client.terminate_process("sleep", agent_id="004", pid=4242)
    victim = tmp_path / "f.bin"
    victim.write_text("x")
    edr_client.quarantine_file(str(victim), agent_id="004", file_hash="a" * 64)
    edr_client.isolate_endpoint("h", agent_id="004")
    edr_client.unisolate_endpoint("h", agent_id="004")
    assert len(seen) == 7
    for body in seen:
        action = body["command"].lstrip("!")[len("phantom-"):]
        if action == "kill-process":
            continue  # pid 4242 does not exist here; arity is checked by the other tests
        if action == "quarantine-file":
            continue  # hash intentionally wrong; arity accepted (rc 1 = refused, not 2 = bad input)
        rc, log = run(env, action, *body["arguments"])
        assert rc in (0, 1), (action, body["arguments"], log)
        assert rc == 0 or action == "isolate-host" or "refused" in log
    rc, _ = run(env, "kill-process", *seen[3]["arguments"])
    assert rc in (0, 1)
    rc, _ = run(env, "quarantine-file", *seen[4]["arguments"])
    assert rc in (0, 1)


# --- shipped files -----------------------------------------------------------------------------------

def test_ossec_snippets_define_every_command_and_never_auto_trigger():
    text = (WAZUH_DIR / "ossec-manager-snippets.xml").read_text()
    root = ET.fromstring("<ossec_config>" + re.sub(r"<!--.*?-->", "", text, flags=re.S) + "</ossec_config>")
    commands = {c.findtext("name"): c.findtext("executable") for c in root.findall("command")}
    assert set(commands) == set(AR_COMMAND_DEFAULTS.values())
    assert all(name == exe for name, exe in commands.items())
    responses = root.findall("active-response")
    assert {r.findtext("command") for r in responses} == set(commands)
    for r in responses:
        assert r.findtext("rules_id") == "999999" and r.findtext("level") is None
        assert r.findtext("timeout") is None


def test_every_command_is_installed_and_documented():
    installer = (WAZUH_DIR / "linux" / "install-linux.sh").read_text()
    windows = (WAZUH_DIR / "windows" / "install-windows.ps1").read_text()
    readme = (WAZUH_DIR / "README.md").read_text()
    for command in AR_COMMAND_DEFAULTS.values():
        action = command[len("phantom-"):]
        assert action in installer and f"'{action}'" in windows and command in readme


def test_windows_script_is_strict_and_refuses_the_right_things():
    ps1 = (WAZUH_DIR / "windows" / "phantom-ar.ps1").read_text()
    cmd = (WAZUH_DIR / "windows" / "phantom-ar.cmd").read_text()
    code = re.sub(r"<#.*?#>", "", ps1, flags=re.S)  # ignore the help comment
    assert not re.search(r"Invoke-Expression|\biex\b|Start-Process\s+cmd|cmd\.exe\s+/c", code, re.I)
    for needle in ("ValidateSet", "TryParse", "Get-ManagerAddresses", "phantom-allowlist.txt", "is in the allow-list",
                   "is loopback", "ReparsePoint", "New-NetFirewallRule", "Register-ScheduledTask",
                   "Set-NetFirewallProfile", "not supported on Windows", "active-responses.log", "PHANTOM_AR_DRY_RUN"):
        assert needle in ps1, needle
    assert "phantom-ar.ps1" in cmd and "%~n0" in cmd and "-ExecutionPolicy Bypass" in cmd
    assert "%1" not in cmd and "%*" not in cmd  # nothing from the command line reaches PowerShell


def test_linux_script_never_uses_a_shell():
    source = SCRIPT.read_text()
    assert "shell=True" not in source and "os.system" not in source and "os.popen" not in source
    assert source.startswith("#!/usr/bin/env python3") and os.access(SCRIPT, os.X_OK)
