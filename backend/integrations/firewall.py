"""Firewall connector backed by Wazuh active response.

block_ip sends Wazuh's standard "firewall-drop" command (override with
WAZUH_AR_BLOCK_COMMAND). The command runs on the alert's Wazuh agent, or on the
agents listed in WAZUH_FIREWALL_AGENT_IDS (comma separated, e.g. a gateway
agent) when that is set. How long a block lasts is governed by the <timeout>
of the active-response block in the manager's ossec.conf, not by this call.

unblock_ip and apply_rate_limit have no built-in Wazuh equivalent: they use
custom commands (WAZUH_AR_UNBLOCK_COMMAND, default "phantom-unblock-ip";
WAZUH_AR_RATE_LIMIT_COMMAND, default "phantom-rate-limit") that must be defined
on the manager with matching scripts on the agents.
"""
import logging
from typing import Any, Dict, List, Optional

from backend.integrations import connector_base as base
from backend.integrations.edr import ar_command, wazuh_ar

logger = logging.getLogger(__name__)


def _firewall_agents(agent_id: Optional[str]) -> List[str]:
    configured = base.read_settings("wazuh_firewall_agent_ids").get("wazuh_firewall_agent_ids", "")
    agents = [a.strip() for a in configured.replace("\n", ",").split(",") if a.strip()]
    if agents:
        return agents
    return [agent_id] if agent_id else []


class FirewallConnector:
    """IP containment through Wazuh active response."""

    provider = "Wazuh Active Response (firewall)"

    def block_ip(
        self,
        ip_address: str,
        agent_id: Optional[str] = None,
        duration_hours: Optional[int] = None,
        direction: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = wazuh_ar.run(
            "block_ip", ip_address, ar_command("wazuh_ar_block_command"),
            _firewall_agents(agent_id),
            arguments=[],
            alert_data={"data": {"srcip": ip_address, **(alert_context or {})}},
            provider=self.provider,
        )
        if duration_hours or direction:
            result["details"]["requested"] = {"duration_hours": duration_hours, "direction": direction}
            result["details"]["note"] = (
                "Block duration and direction are set by the active-response configuration "
                "on the Wazuh manager, not per request."
            )
        return result

    def unblock_ip(
        self,
        ip_address: str,
        agent_id: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return wazuh_ar.run(
            "unblock_ip", ip_address, ar_command("wazuh_ar_unblock_command"),
            _firewall_agents(agent_id),
            arguments=[ip_address],
            alert_data={"data": {"srcip": ip_address, **(alert_context or {})}},
            provider=self.provider,
        )

    def apply_rate_limit(
        self,
        ip_address: str,
        rate: str = "10/minute",
        agent_id: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return wazuh_ar.run(
            "apply_rate_limit", ip_address, ar_command("wazuh_ar_rate_limit_command"),
            _firewall_agents(agent_id),
            arguments=[ip_address, rate],
            alert_data={"data": {"srcip": ip_address, "rate": rate, **(alert_context or {})}},
            provider=self.provider,
        )


firewall_client = FirewallConnector()
