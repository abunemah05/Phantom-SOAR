"""EDR connector backed by the Wazuh manager's active-response API.

When SIEM settings (siem_manager_url, siem_user, siem_password) are configured,
each action authenticates against the Wazuh API and sends an active-response
command to the alert's Wazuh agent. Otherwise the action is simulated (when
simulation mode is on) or skipped.

Host isolation, process termination and file quarantine are not built into
Wazuh: they use custom active-response commands whose names are configurable
through environment variables, and they only work when a matching <command>
is defined in the manager's ossec.conf and the script is deployed on the agents:

    WAZUH_AR_ISOLATE_COMMAND     (default "phantom-isolate-host")
    WAZUH_AR_UNISOLATE_COMMAND   (default "phantom-unisolate-host")
    WAZUH_AR_KILL_COMMAND        (default "phantom-kill-process")
    WAZUH_AR_QUARANTINE_COMMAND  (default "phantom-quarantine-file")
"""
import logging
from typing import Any, Dict, List, Optional

import httpx

from backend.integrations import connector_base as base

logger = logging.getLogger(__name__)

WAZUH_REQUIRED = ("siem_manager_url", "siem_user", "siem_password")

AR_COMMAND_DEFAULTS = {
    "wazuh_ar_isolate_command": "phantom-isolate-host",
    "wazuh_ar_unisolate_command": "phantom-unisolate-host",
    "wazuh_ar_kill_command": "phantom-kill-process",
    "wazuh_ar_quarantine_command": "phantom-quarantine-file",
    "wazuh_ar_block_command": "firewall-drop",
    "wazuh_ar_unblock_command": "phantom-unblock-ip",
    "wazuh_ar_rate_limit_command": "phantom-rate-limit",
}


def ar_command(setting_key: str) -> str:
    """Active-response command name (env override, e.g. WAZUH_AR_ISOLATE_COMMAND)."""
    value = base.read_settings(setting_key).get(setting_key)
    return value or AR_COMMAND_DEFAULTS[setting_key]


class WazuhActiveResponse:
    """Minimal Wazuh manager API client: authenticate, then PUT /active-response."""

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
        cfg = base.read_settings(*WAZUH_REQUIRED, "siem_verify_tls")
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

        url = cfg["siem_manager_url"].rstrip("/")
        verify = base.as_bool(cfg.get("siem_verify_tls"), default=True)
        body = {"command": command, "arguments": arguments or [], "alert": alert_data or {}}
        try:
            with base.http_client(verify=verify) as client:
                auth = client.post(
                    f"{url}/security/user/authenticate",
                    auth=(cfg["siem_user"], cfg["siem_password"]),
                )
                auth.raise_for_status()
                token = ((auth.json() or {}).get("data") or {}).get("token")
                if not token:
                    return base.failed(action, target, provider, "Wazuh authentication succeeded but returned no token.")

                resp = client.put(
                    f"{url}/active-response",
                    params={"agents_list": ",".join(agent_ids)},
                    headers={"Authorization": f"Bearer {token}"},
                    json=body,
                )
                resp.raise_for_status()
                payload = resp.json() or {}
        except httpx.HTTPError as exc:
            return base.failed(action, target, provider, base.describe_http_error(exc), command=command, agents=agent_ids)
        except ValueError as exc:
            return base.failed(action, target, provider, f"Wazuh returned a non-JSON response: {exc}", command=command)

        data = payload.get("data") or {}
        affected = [str(a) for a in (data.get("affected_items") or [])]
        failed_items = data.get("failed_items") or []
        details = {
            "manager": url,
            "command": command,
            "arguments": body["arguments"],
            "agents_requested": agent_ids,
            "affected_agents": affected,
            "failed_items": failed_items,
            "message": payload.get("message"),
        }
        if failed_items or not affected:
            reasons = "; ".join(
                str((item.get("error") or {}).get("message") or item) for item in failed_items
            ) or "No agent accepted the active-response command."
            return base.failed(action, target, provider, reasons, details=details, command=command, agents=agent_ids)

        logger.info(f"[{provider}] '{command}' accepted by agent(s) {affected} for {action} on {target}.")
        return base.live(action, target, provider, details, command=command, agents=affected)


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
