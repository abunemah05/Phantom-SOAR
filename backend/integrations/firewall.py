"""Firewall connector backed by Wazuh active response.

block_ip sends the custom "phantom-block-ip" script (override with the
wazuh_ar_block_command setting / WAZUH_AR_BLOCK_COMMAND) with the arguments
[ip, duration_hours, direction]; the agent script (wazuh/linux/phantom-ar,
wazuh/windows/phantom-ar.ps1) honours both: the block is removed automatically
when the duration ends and direction picks inbound, outbound or both.

Wazuh's stock "firewall-drop" script ignores arguments and only reads
alert.data.srcip, and a command sent through the API with the "!" prefix gets no
timeout, so if the block command is set to firewall-drop the duration and
direction cannot be honoured; the result then says so.

unblock_ip and apply_rate_limit use phantom-unblock-ip (WAZUH_AR_UNBLOCK_COMMAND)
and phantom-rate-limit (WAZUH_AR_RATE_LIMIT_COMMAND). The command runs on the
alert's Wazuh agent, or on the agents listed in WAZUH_FIREWALL_AGENT_IDS (comma
separated, e.g. a gateway agent) when that is set.

New settings (all read through integration_config, env fallback = upper-case name):
    wazuh_default_block_hours  hours a block lasts when the request gives none (default 24, 0 = until unblocked)
    wazuh_default_rate_limit_hours  hours a rate limit lasts when the request gives none (default 24, 0 = until removed)
"""
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional

from backend.integrations import connector_base as base
from backend.integrations.edr import ar_command, wazuh_ar

logger = logging.getLogger(__name__)

DIRECTIONS = ("inbound", "outbound", "both")
MAX_DURATION_HOURS = 720
DEFAULT_BLOCK_HOURS = 24
_RATE_RE = re.compile(r"^[1-9]\d{0,5}/(second|minute|hour|day)$")


def _firewall_agents(agent_id: Optional[str]) -> List[str]:
    configured = base.read_settings("wazuh_firewall_agent_ids").get("wazuh_firewall_agent_ids", "")
    agents = [a.strip() for a in configured.replace("\n", ",").split(",") if a.strip()]
    if agents:
        return agents
    return [agent_id] if agent_id else []


def _clean_ip(ip_address: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(str(ip_address).strip())
    except ValueError:
        return None
    # the agent scripts reject ::ffff:a.b.c.d (it would bypass their IPv4 manager/allow-list checks): send the IPv4 form
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _hours_setting(key: str, fallback: int) -> int:
    raw = base.read_settings(key).get(key, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return fallback
    return value if 0 <= value <= MAX_DURATION_HOURS else fallback


def _duration(value: Any) -> Optional[int]:
    """Validated hours (1..720) or None when invalid; bool and non-integers are invalid."""
    if isinstance(value, bool):
        return None
    try:
        hours = int(value)
    except (TypeError, ValueError):
        return None
    return hours if 1 <= hours <= MAX_DURATION_HOURS and str(value).strip() == str(hours) else None


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
        ip = _clean_ip(ip_address)
        if ip is None:
            return base.failed("block_ip", ip_address, self.provider, f"Not a valid IP address: {ip_address!r}")
        if direction not in (None, ""):
            if direction not in DIRECTIONS:
                return base.failed("block_ip", ip, self.provider,
                                   f"Invalid direction {direction!r}; use one of {', '.join(DIRECTIONS)}.")
        direction = direction or "inbound"
        if duration_hours in (None, ""):
            hours = _hours_setting("wazuh_default_block_hours", DEFAULT_BLOCK_HOURS)
        else:
            hours = _duration(duration_hours)
            if hours is None:
                return base.failed("block_ip", ip, self.provider,
                                   f"Invalid duration_hours {duration_hours!r}; use a whole number from 1 to {MAX_DURATION_HOURS}.")

        command = ar_command("wazuh_ar_block_command")
        stock = command.lstrip("!").startswith("firewall-drop")
        arguments = [] if stock else [ip, str(hours), direction]
        result = wazuh_ar.run(
            "block_ip", ip, command,
            _firewall_agents(agent_id),
            arguments=arguments,
            alert_data={"data": {"srcip": ip, **(alert_context or {})}},
            provider=self.provider,
        )
        result["details"]["requested"] = {"duration_hours": hours, "direction": direction}
        if stock:
            result["details"]["honoured"] = False
            result["details"]["note"] = (
                "The configured block command is Wazuh's stock firewall-drop, which ignores duration "
                "and direction; use phantom-block-ip to have them applied."
            )
        else:
            result["details"]["honoured"] = True
        return result

    def unblock_ip(
        self,
        ip_address: str,
        agent_id: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ip = _clean_ip(ip_address)
        if ip is None:
            return base.failed("unblock_ip", ip_address, self.provider, f"Not a valid IP address: {ip_address!r}")
        return wazuh_ar.run(
            "unblock_ip", ip, ar_command("wazuh_ar_unblock_command"),
            _firewall_agents(agent_id),
            arguments=[ip],
            alert_data={"data": {"srcip": ip, **(alert_context or {})}},
            provider=self.provider,
        )

    def apply_rate_limit(
        self,
        ip_address: str,
        rate: str = "10/minute",
        agent_id: Optional[str] = None,
        alert_context: Optional[Dict[str, Any]] = None,
        duration_hours: Optional[int] = None,
    ) -> Dict[str, Any]:
        ip = _clean_ip(ip_address)
        if ip is None:
            return base.failed("apply_rate_limit", ip_address, self.provider, f"Not a valid IP address: {ip_address!r}")
        rate = (rate or "10/minute").strip().lower()
        if not _RATE_RE.match(rate):
            return base.failed("apply_rate_limit", ip, self.provider,
                               f"Invalid rate {rate!r}; use e.g. '10/minute' or '5/second'.")
        if duration_hours in (None, ""):
            hours = _hours_setting("wazuh_default_rate_limit_hours", DEFAULT_BLOCK_HOURS)
        else:
            hours = _duration(duration_hours)
            if hours is None:
                return base.failed("apply_rate_limit", ip, self.provider,
                                   f"Invalid duration_hours {duration_hours!r}; use a whole number from 1 to {MAX_DURATION_HOURS}.")
        result = wazuh_ar.run(
            "apply_rate_limit", ip, ar_command("wazuh_ar_rate_limit_command"),
            _firewall_agents(agent_id),
            arguments=[ip, rate, str(hours)],
            alert_data={"data": {"srcip": ip, "rate": rate, **(alert_context or {})}},
            provider=self.provider,
        )
        result["details"]["requested"] = {"rate": rate, "duration_hours": hours}
        return result


firewall_client = FirewallConnector()
