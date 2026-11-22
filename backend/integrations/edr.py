"""EDR connector backed by the Wazuh manager's active-response API.

When SIEM settings (siem_manager_url, siem_user, siem_password) are configured,
each action authenticates against the Wazuh API (the JWT is cached until shortly
before it expires) and sends an active-response command to the alert's Wazuh
agent. Otherwise the action is simulated (when simulation mode is on) or skipped.

Request shape, checked against the official Wazuh sources and docs (Wazuh manager and agents >= 4.2.0):

* PUT /active-response?agents_list=<id>[,<id>...]   agents_list is "a list of agent IDs (separated by
  comma), all agents selected by default if not specified" (API spec, parameter agents_list), so omitting it
  would target EVERY agent: this client never sends a request without agent ids and refuses agent 000, the
  manager itself (API error 1703).
* body {"command": ..., "arguments": [...], "alert": {"data": {...}}}; "arguments" is an array of strings,
  "alert" an object with a "data" object, "command" is the only required field. Spec (ActiveResponseBody):
  https://github.com/wazuh/wazuh/blob/v4.14.0/api/api/spec/spec.yaml
  Rendered reference: https://documentation.wazuh.com/current/user-manual/api/reference.html
  (Active-response > Run command).
* The body has NO "custom" field, on purpose. Older managers (4.2 to 4.7) accepted `"custom": bool`, but it only
  changed anything for agents older than 4.2.0 (it prepended "!" to the name for the legacy text message);
  for agents >= 4.2.0 the JSON message is built from the command exactly as sent
  (create_json_message in https://github.com/wazuh/wazuh/blob/v4.7.0/framework/wazuh/core/active_response.py).
  Managers >= 4.8.0 REMOVED the field ("Removed `custom` parameter from `PUT /active-response` endpoint",
  https://github.com/wazuh/wazuh/blob/v4.8.0/CHANGELOG.md, PR 17048) and reject unknown body keys with HTTP 400
  "Invalid field found ['custom']" (Body.get_kwargs in api/api/models/base_model_.py). Sending "custom": true
  would therefore break every manager >= 4.8. The version-independent way to run a custom script is the
  documented "!" prefix: "If this value starts with `!`, then it refers to a script name instead of a command
  name" (spec text above).
* A command that does not start with "!" must be a name listed in the manager's etc/shared/ar.conf (otherwise
  error 1652 "The command used is not defined in the configuration"; validate_command in
  https://github.com/wazuh/wazuh/blob/v4.14.0/framework/wazuh/core/active_response.py). Those names are
  "<command name><timeout>" (e.g. "firewall-drop600"; src/config/active-response.c), so the bare name
  "firewall-drop" is rejected. A command starting with "!" names a script in the agent's active-response/bin
  directory that execd runs directly, with no <command>/<active-response> blocks and no automatic
  timeout/"delete" message (GetCommandbyName in https://github.com/wazuh/wazuh/blob/v4.9.0/src/os_execd/exec.c;
  the API only accepts an optional leading "!" followed by word characters, "-", ".", "/", "\\" and ":"
  in the name, api/api/validator.py, so "!phantom-block-ip.cmd" is valid).
* Agents older than 4.2.0 receive a legacy string message instead of JSON; the scripts in wazuh/ require agents
  >= 4.2.0 and so a manager >= 4.2.0. Other errors surfaced in failed_items: 1707 (agent not active), 1750
  (active-response disabled in the agent's ossec.conf).
* POST /security/user/authenticate (HTTP Basic) returns {"data": {"token": jwt}}; with ?raw=true (what the
  docs recommend for curl) the body is the bare token instead. This client uses the JSON form because it also
  carries error details. The token is sent as "Authorization: Bearer <jwt>" and lives auth_token_exp_timeout
  seconds (default 900).
  https://documentation.wazuh.com/current/user-manual/api/getting-started.html
* TLS: the manager API uses a self-signed certificate by default (the docs use curl -k for that reason); here
  verification stays on unless siem_verify_tls=false, and wazuh_ca_bundle pins the CA (see below).

So by default every command name is sent with a "!" prefix (setting
wazuh_ar_script_prefix=true). The scripts shipped in the repo's wazuh/ folder
implement the phantom-* commands. Windows agents need a ".cmd" launcher in
the agent's active-response/bin folder, so agents listed in wazuh_windows_agent_ids get ".cmd"
appended to the script name.

Command names are configurable (the setting wins over the environment variable):

    wazuh_ar_isolate_command     WAZUH_AR_ISOLATE_COMMAND     (default "phantom-isolate-host")
    wazuh_ar_unisolate_command   WAZUH_AR_UNISOLATE_COMMAND   (default "phantom-unisolate-host")
    wazuh_ar_kill_command        WAZUH_AR_KILL_COMMAND        (default "phantom-kill-process")
    wazuh_ar_quarantine_command  WAZUH_AR_QUARANTINE_COMMAND  (default "phantom-quarantine-file")

TLS: siem_verify_tls (default true) toggles certificate verification and
wazuh_ca_bundle points at a CA bundle (PEM) that signs the manager certificate.
"""
import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

from backend.integrations import connector_base as base

logger = logging.getLogger(__name__)

WAZUH_REQUIRED = ("siem_manager_url", "siem_user", "siem_password")
WAZUH_OPTIONAL = ("siem_verify_tls", "wazuh_ca_bundle", "wazuh_ar_script_prefix", "wazuh_windows_agent_ids")

AR_COMMAND_DEFAULTS = {
    "wazuh_ar_isolate_command": "phantom-isolate-host",
    "wazuh_ar_unisolate_command": "phantom-unisolate-host",
    "wazuh_ar_kill_command": "phantom-kill-process",
    "wazuh_ar_quarantine_command": "phantom-quarantine-file",
    "wazuh_ar_block_command": "phantom-block-ip",
    "wazuh_ar_unblock_command": "phantom-unblock-ip",
    "wazuh_ar_rate_limit_command": "phantom-rate-limit",
}

WINDOWS_SUFFIX = ".cmd"
MANAGER_AGENT_ID = "000"  # agent 000 is the Wazuh manager itself: never a response target
_AGENT_ID_RE = re.compile(r"^\d{1,8}$")

TOKEN_REFRESH_MARGIN = 60  # seconds before exp at which a cached token is no longer used


def ar_command(setting_key: str) -> str:
    """Active-response command name (setting, then env, e.g. WAZUH_AR_ISOLATE_COMMAND, then default)."""
    value = base.read_settings(setting_key).get(setting_key)
    return value or AR_COMMAND_DEFAULTS[setting_key]


# --- JWT cache ---------------------------------------------------------------------

_now = time.time  # patchable in tests
_token_lock = threading.Lock()
_token_cache: Dict[Tuple[str, str, str, str], Tuple[str, float]] = {}


def clear_token_cache() -> None:
    with _token_lock:
        _token_cache.clear()


def jwt_expiry(token: str) -> Optional[float]:
    """The 'exp' claim of a JWT, read WITHOUT verifying the signature (only used to schedule a refresh)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload.encode())).get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


def _cache_key(url: str, user: str, password: str, verify: Union[bool, str]) -> Tuple[str, str, str, str]:
    digest = hashlib.sha256(password.encode()).hexdigest()[:16]
    return (url, user, digest, str(verify))


def get_token(
    client: httpx.Client, url: str, user: str, password: str,
    verify: Union[bool, str] = True, force_refresh: bool = False,
) -> Tuple[str, bool, int]:
    """Return (token, served_from_cache, login_attempts), logging in only when needed.

    Thread-safe. A cached token is reused until TOKEN_REFRESH_MARGIN seconds before its exp claim.
    A token without a readable exp is used once and never cached.
    """
    key = _cache_key(url, user, password, verify)
    with _token_lock:
        cached = _token_cache.get(key)
        if cached and not force_refresh and cached[1] - TOKEN_REFRESH_MARGIN > _now():
            return cached[0], True, 0
        _token_cache.pop(key, None)
        resp = base.request_with_retry(
            client, "POST", f"{url}/security/user/authenticate", auth=(user, password), idempotent=True,
        )
        attempts = base.attempts_of(resp)
        resp.raise_for_status()
        token = ((resp.json() or {}).get("data") or {}).get("token")
        if not token:
            raise WazuhAuthError("Wazuh authentication succeeded but returned no token.")
        exp = jwt_expiry(token)
        if exp is not None:
            _token_cache[key] = (token, exp)
        return token, False, attempts


class WazuhAuthError(Exception):
    pass


# --- Client ------------------------------------------------------------------------

def _wire_command(command: str, windows: bool, use_prefix: bool) -> str:
    """The name to put in the request: '!' + script name, with '.cmd' for Windows agents."""
    if not use_prefix:
        return command
    name = command if command.startswith("!") else "!" + command
    if windows and not os.path.splitext(name)[1]:
        name += WINDOWS_SUFFIX
    return name


def _split_ids(value: str) -> List[str]:
    return [a.strip() for a in (value or "").replace("\n", ",").split(",") if a.strip()]


class WazuhActiveResponse:
    """Minimal Wazuh manager API client: authenticate (cached JWT), then PUT /active-response."""

    provider = "Wazuh Active Response"

    def run(
        self,
        action: str,
        target: Optional[str],
        command: str,
        agent_ids: List[str],
        arguments: Optional[List[str]] = None,
        alert_data: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        provider = provider or self.provider
        cfg = base.read_settings(*WAZUH_REQUIRED, *WAZUH_OPTIONAL)
        missing = base.missing_settings(cfg, WAZUH_REQUIRED)
        if missing:
            return base.unconfigured(action, target, provider, missing, command=command, agents=agent_ids)

        agent_ids = [str(a).strip() for a in agent_ids if a is not None and str(a).strip()]
        if not agent_ids:
            return base.failed(
                action, target, provider,
                "No Wazuh agent id is known for this target (the alert has no agent.id); "
                "pass params.agent_id to choose the agent.",
                command=command,
            )
        bad = [a for a in agent_ids if not _AGENT_ID_RE.match(a)]
        if bad:
            return base.failed(action, target, provider, f"Invalid Wazuh agent id: {bad[0]!r}", command=command)
        if any(a.zfill(3) == MANAGER_AGENT_ID for a in agent_ids):
            return base.failed(
                action, target, provider,
                "Refusing to run an active response on agent 000 (the Wazuh manager itself).",
                command=command,
            )

        url = cfg["siem_manager_url"].rstrip("/")
        verify, tls_details, tls_error = self._tls(cfg)
        if tls_error:
            return base.failed(action, target, provider, tls_error, details=tls_details, command=command)

        use_prefix = base.as_bool(cfg.get("wazuh_ar_script_prefix"), default=True)
        windows_ids = {a.zfill(3) for a in _split_ids(cfg.get("wazuh_windows_agent_ids", ""))}
        groups: Dict[str, List[str]] = {}
        for agent in agent_ids:
            groups.setdefault(_wire_command(command, agent.zfill(3) in windows_ids, use_prefix), []).append(agent)

        body_args = list(arguments or [])
        affected: List[str] = []
        failed_items: List[Any] = []
        messages: List[str] = []
        attempts = 0
        token_cached = True
        try:
            with base.http_client(verify=verify) as client:
                for wire, ids in groups.items():
                    body = {"command": wire, "arguments": body_args, "alert": alert_data or {}}
                    payload, tries, cached = self._send(client, url, cfg, verify, ids, body)
                    attempts += tries
                    token_cached = token_cached and cached
                    data = payload.get("data") or {}
                    affected += [str(a) for a in (data.get("affected_items") or [])]
                    failed_items += data.get("failed_items") or []
                    if payload.get("message"):
                        messages.append(str(payload["message"]))
        except WazuhAuthError as exc:
            return base.failed(action, target, provider, str(exc), details={**tls_details, "attempts": attempts}, command=command)
        except httpx.HTTPError as exc:
            attempts += getattr(exc, "phantom_attempts", 0)
            return base.failed(
                action, target, provider, base.describe_http_error(exc),
                details={**tls_details, "attempts": attempts}, command=command, agents=agent_ids,
            )
        except ValueError as exc:
            return base.failed(
                action, target, provider, f"Wazuh returned a non-JSON response: {exc}",
                details={**tls_details, "attempts": attempts}, command=command,
            )

        details = {
            "manager": url,
            "command": command,
            "wire_commands": list(groups),
            "arguments": body_args,
            "agents_requested": agent_ids,
            "affected_agents": affected,
            "failed_items": failed_items,
            "message": "; ".join(messages) or None,
            "attempts": attempts,
            "token_cached": token_cached,
            "delivery": "queued_by_manager",
            "confirmation": "Wazuh manager accepted and sent the command to the agent; the agent's own result is only in its active-responses.log",
            **tls_details,
        }
        if failed_items or not affected:
            reasons = "; ".join(
                str((item.get("error") or {}).get("message") or item) for item in failed_items
            ) or "No agent accepted the active-response command."
            return base.failed(action, target, provider, reasons, details=details, command=command, agents=agent_ids)

        logger.info(f"[{provider}] '{command}' accepted by agent(s) {affected} for {action} on {target}.")
        return base.live(action, target, provider, details, command=command, agents=affected)

    @staticmethod
    def _tls(cfg: Dict[str, str]) -> Tuple[Union[bool, str], Dict[str, Any], Optional[str]]:
        """(httpx verify value, details to record, error). Verification off logs a loud warning."""
        verify_on = base.as_bool(cfg.get("siem_verify_tls"), default=True)
        bundle = (cfg.get("wazuh_ca_bundle") or "").strip()
        if not verify_on:
            logger.warning(
                "TLS CERTIFICATE VERIFICATION IS DISABLED for the Wazuh manager connection "
                "(siem_verify_tls=false): the API password and token can be intercepted. "
                "Set wazuh_ca_bundle to your CA certificate and re-enable verification."
            )
            return False, {"tls_verified": False}, None
        if bundle:
            if not os.path.isfile(bundle):
                return True, {"tls_verified": True}, f"wazuh_ca_bundle does not point to a readable file: {bundle}"
            return bundle, {"tls_verified": True, "tls_ca_bundle": bundle}, None
        return True, {"tls_verified": True}, None

    @staticmethod
    def _send(
        client: httpx.Client, url: str, cfg: Dict[str, str], verify: Union[bool, str],
        agent_ids: List[str], body: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], int, bool]:
        """PUT the command; on 401 (expired/revoked token) log in again once and resend."""
        attempts = 0
        token, from_cache, login_tries = get_token(client, url, cfg["siem_user"], cfg["siem_password"], verify)
        attempts += login_tries
        all_cached = from_cache
        for retry_auth in (True, False):
            resp = base.request_with_retry(
                client, "PUT", f"{url}/active-response",
                idempotent=False,  # running a response twice is not harmless
                params={"agents_list": ",".join(agent_ids)},
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
            attempts += base.attempts_of(resp)
            if resp.status_code == 401 and retry_auth:
                token, _, login_tries = get_token(
                    client, url, cfg["siem_user"], cfg["siem_password"], verify, force_refresh=True)
                attempts += login_tries
                all_cached = False
                continue
            resp.raise_for_status()
            return resp.json() or {}, attempts, all_cached
        raise AssertionError("unreachable")  # pragma: no cover


wazuh_ar = WazuhActiveResponse()


class EDRConnector:
    """Endpoint response actions sent through Wazuh active response."""

    provider = "Wazuh Active Response (EDR)"

    def isolate_endpoint(
        self,
        hostname: str,
        agent_id: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return wazuh_ar.run(
            "isolate_endpoint", hostname, ar_command("wazuh_ar_isolate_command"),
            [agent_id] if agent_id else [],
            arguments=[],
            alert_data={"data": {"hostname": hostname, **(alert_context or {})}},
            provider=self.provider,
        )

    def unisolate_endpoint(
        self,
        hostname: str,
        agent_id: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return wazuh_ar.run(
            "unisolate_endpoint", hostname, ar_command("wazuh_ar_unisolate_command"),
            [agent_id] if agent_id else [],
            arguments=[],
            alert_data={"data": {"hostname": hostname, **(alert_context or {})}},
            provider=self.provider,
        )

    def terminate_process(
        self,
        process_name: str,
        agent_id: Optional[str] = None,
        pid: Optional[int] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        arguments = [process_name] + ([str(pid)] if pid else [])
        return wazuh_ar.run(
            "terminate_process", process_name, ar_command("wazuh_ar_kill_command"),
            [agent_id] if agent_id else [],
            arguments=arguments,
            alert_data={"data": {"process": process_name, "pid": pid, **(alert_context or {})}},
            provider=self.provider,
        )

    def quarantine_file(
        self,
        file_path: str,
        agent_id: Optional[str] = None,
        file_hash: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        arguments = [file_path] + ([file_hash] if file_hash else [])
        return wazuh_ar.run(
            "quarantine_file", file_path, ar_command("wazuh_ar_quarantine_command"),
            [agent_id] if agent_id else [],
            arguments=arguments,
            alert_data={"data": {"file": file_path, "hash": file_hash, **(alert_context or {})}},
            provider=self.provider,
        )


edr_client = EDRConnector()
