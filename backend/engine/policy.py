"""Guardrails for automated and human-requested response actions.

evaluate_action() decides whether an action may run against a target and
whether it needs analyst approval first. Actors:

    "playbook"  automated playbook steps (HOTL engine)
    "agent"     an external AI agent using the agent API
    "analyst"   a signed-in human analyst

Automated actors (playbook, agent) can never touch protected hosts, users or
IPs; an analyst can, and the decision notes it.
"""
import fnmatch
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Union

from sqlalchemy.orm import Session

from backend import integration_config
from backend.engine.actions import (
    ACTION_CATALOG,
    TARGET_ENTITY_KEYS,
    resolve_action_name,
    validate_params,
)

logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

ACTORS = {"playbook", "agent", "analyst"}
AUTOMATED_ACTORS = {"playbook", "agent"}
AUTONOMY_LEVELS = {"recommend_only", "low_impact", "policy"}

# Actions that restrict traffic: never aimed at addresses that make no sense to block.
IP_RESTRICTING_ACTIONS = {"block_ip", "apply_rate_limit"}

# "Private" for policy purposes: internal address space. Documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are not included: they are not
# routable and are used as stand-in public addresses in lab scenarios.
PRIVATE_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
]

_ENTITY_KEYS = ("hosts", "ips", "users", "hashes", "files", "processes", "domains", "urls")
_JUNK_VALUES = {"", "-", "none", "null", "n/a", "na", "unknown", "(null)"}
_NON_IDENTITY_USERS = {"system", "local service", "network service", "anonymous logon", "nt authority\\system"}


@dataclass
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "requires_approval": self.requires_approval, "reasons": list(self.reasons)}


# --- Alert entities -----------------------------------------------------------

def _values(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            out.extend(_values(item))
        return out
    if isinstance(value, dict):
        for key in ("name", "hostname", "value", "path", "login"):
            if value.get(key):
                return _values(value[key])
        return []
    text = str(value).strip()
    return [] if text.lower() in _JUNK_VALUES else [text]


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _valid_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _dedupe(values: Iterable[str], case_insensitive: bool = True) -> List[str]:
    seen = set()
    out = []
    for value in values:
        key = value.lower() if case_insensitive else value
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def get_alert_entities(alert: Any, iocs: Optional[Iterable[Any]] = None) -> Dict[str, List[str]]:
    """Hosts, IPs, users, hashes, files, processes, domains and URLs named by an alert.

    Derived from the alert's raw telemetry (Wazuh, EDR and XDR field names) and its
    IoC artifacts. `alert` may be an Alert row or a dict with a raw_payload key.
    """
    raw = (alert.get("raw_payload") if isinstance(alert, dict) else getattr(alert, "raw_payload", None)) or {}
    if iocs is None and not isinstance(alert, dict):
        iocs = getattr(alert, "ioc_artifacts", None) or []
    iocs = list(iocs or [])

    data = _dict(raw.get("data"))
    agent = _dict(raw.get("agent"))
    win = _dict(_dict(data.get("win")).get("eventdata"))
    audit = _dict(data.get("audit"))
    syscheck = _dict(raw.get("syscheck"))
    process = _dict(raw.get("process"))
    file_info = _dict(raw.get("file"))

    hosts = _values(agent.get("name")) + _values(agent.get("hostname"))
    for key in ("hostname", "host", "device", "endpoint", "hosts"):
        hosts += _values(raw.get(key))
    hosts += _values(data.get("hostname")) + _values(data.get("host"))

    ip_candidates = _values(agent.get("ip"))
    for key in ("srcip", "dstip", "src_ip", "dst_ip", "client_ip", "attacker_ip", "remote_ip"):
        ip_candidates += _values(data.get(key))
    for key in ("src_ip", "dst_ip", "ip", "ips", "remote_ip"):
        ip_candidates += _values(raw.get(key))

    users = []
    for key in ("srcuser", "dstuser", "user", "username", "account"):
        users += _values(data.get(key))
    users += _values(win.get("targetUserName")) + _values(win.get("subjectUserName"))
    for key in ("user", "username", "users", "account"):
        users += _values(raw.get(key))
    users = [u for u in users if u.lower() not in _NON_IDENTITY_USERS]

    processes = []
    for key in ("process", "process_name", "image"):
        processes += _values(data.get(key))
    processes += _values(win.get("image")) + _values(audit.get("exe"))
    processes += _values(process.get("name")) + _values(raw.get("process_name"))

    files = []
    for key in ("file", "file_path", "path", "target_file"):
        files += _values(data.get(key))
    files += _values(syscheck.get("path")) + _values(win.get("targetFilename"))
    files += _values(raw.get("file_path")) + _values(file_info.get("path"))

    hashes = []
    for key in ("md5", "sha1", "sha256", "file_hash", "hash"):
        hashes += _values(data.get(key))
        hashes += _values(raw.get(key))
    for key in ("md5_after", "sha1_after", "sha256_after"):
        hashes += _values(syscheck.get(key))
    hashes += _values(file_info.get("hash")) + _values(process.get("hash"))

    domains = _values(data.get("domain")) + _values(raw.get("domain"))
    urls = _values(data.get("url")) + _values(data.get("target_url")) + _values(raw.get("url"))

    for ioc in iocs:
        kind = str(getattr(ioc, "artifact_type", "") or "").lower()
        value = str(getattr(ioc, "value", "") or "").strip()
        if not value:
            continue
        if kind == "ip":
            ip_candidates.append(value)
        elif kind == "hash":
            hashes.append(value)
        elif kind == "domain":
            domains.append(value)
        elif kind == "url":
            urls.append(value)

    ips = [ip for ip in (_valid_ip(v) for v in ip_candidates) if ip]

    return {
        "hosts": _dedupe(hosts),
        "ips": _dedupe(ips),
        "users": _dedupe(users),
        "hashes": _dedupe(h.lower() for h in hashes),
        "files": _dedupe(files),
        "processes": _dedupe(processes),
        "domains": _dedupe(d.lower() for d in domains),
        "urls": _dedupe(urls, case_insensitive=False),
    }


# --- Settings -----------------------------------------------------------------

def _min_confidence(db: Optional[Session]) -> float:
    try:
        value = float(integration_config.get_setting("agent_min_confidence", db=db))
    except (TypeError, ValueError):
        value = 0.85
    return min(max(value, 0.0), 1.0)


def _autonomy(db: Optional[Session]) -> str:
    value = integration_config.get_setting("agent_autonomy", db=db).strip().lower()
    return value if value in AUTONOMY_LEVELS else "recommend_only"


def _matches_pattern(value: str, patterns: List[str]) -> bool:
    lowered = value.lower()
    return any(fnmatch.fnmatchcase(lowered, p.lower()) for p in patterns)


def _ip_in_list(ip: IPAddress, entries: List[str]) -> bool:
    for entry in entries:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_private_range(ip: IPAddress) -> bool:
    return any(ip.version == net.version and ip in net for net in PRIVATE_NETWORKS)


def _never_block_reason(ip: IPAddress) -> Optional[str]:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    return None


def _alert_host(alert: Any) -> Optional[str]:
    raw = getattr(alert, "raw_payload", None) or {}
    agent = _dict(raw.get("agent"))
    return agent.get("name") or agent.get("hostname")


# --- Evaluation ---------------------------------------------------------------

def evaluate_action(
    db: Optional[Session],
    alert: Any,
    action: str,
    target: Optional[str],
    params: Optional[Dict[str, Any]] = None,
    actor: str = "playbook",
    confidence: Optional[float] = None,
) -> PolicyDecision:
    """Decide whether `actor` may run `action` on `target` for `alert`, and whether it needs approval."""
    reasons: List[str] = []

    if actor not in ACTORS:
        return PolicyDecision(False, False, [f"Unknown actor '{actor}'."])

    canonical = resolve_action_name(action)
    if canonical is None:
        return PolicyDecision(False, False, [f"Unknown action '{action}': not in the action catalog."])
    spec = ACTION_CATALOG[canonical]
    target_type = spec["target_type"]
    automated = actor in AUTOMATED_ACTORS

    param_errors = validate_params(canonical, params)
    if param_errors:
        return PolicyDecision(False, False, param_errors)

    target = str(target).strip() if target is not None else None
    if target_type != "none" and not target:
        return PolicyDecision(False, False, [f"{canonical} needs a {target_type} target."])
    if target_type == "none":
        target = None

    ip_obj = None
    if target_type == "ip":
        try:
            ip_obj = ipaddress.ip_address(target)
        except ValueError:
            return PolicyDecision(False, False, [f"'{target}' is not a valid IP address."])
        target = str(ip_obj)

    if actor == "agent" and target_type != "none":
        entities = get_alert_entities(alert)
        allowed_values = entities.get(TARGET_ENTITY_KEYS[target_type], [])
        if target_type == "ip":
            known = {v for v in allowed_values}
            in_alert = target in known
        else:
            in_alert = target.lower() in {v.lower() for v in allowed_values}
        if not in_alert:
            return PolicyDecision(False, False, [
                f"Target '{target}' is not a {target_type} named in alert #{getattr(alert, 'alert_id', '?')}; "
                "agents may only act on the alert's own entities."
            ])

    # Protected assets.
    protected_hit = None
    if target_type == "host" or spec["connector"] == "edr":
        host = target if target_type == "host" else _alert_host(alert)
        if host and _matches_pattern(host, integration_config.get_list("protected_hosts", db=db)):
            protected_hit = f"host '{host}' is on the protected hosts list"
    if target_type == "user" and _matches_pattern(target, integration_config.get_list("protected_users", db=db)):
        protected_hit = f"user '{target}' is on the protected users list"
    if ip_obj is not None and _ip_in_list(ip_obj, integration_config.get_list("protected_ips", db=db)):
        protected_hit = f"IP {target} is on the protected IPs list"
    if protected_hit:
        if automated:
            return PolicyDecision(False, False, [f"Denied: {protected_hit}; automation may not act on it."])
        reasons.append(f"Note: {protected_hit}; allowed because an analyst requested it.")

    requires_approval = False

    if ip_obj is not None and canonical in IP_RESTRICTING_ACTIONS:
        never = _never_block_reason(ip_obj)
        if never:
            return PolicyDecision(False, False, [f"Denied: {target} is a {never} address and is never blocked."])
        if is_private_range(ip_obj):
            if automated:
                requires_approval = True
                reasons.append(f"{target} is in a private range; blocking internal addresses needs analyst approval.")
            else:
                reasons.append(f"Note: {target} is an internal (private-range) address.")

    if automated and not integration_config.get_bool("hotl_enabled", db=db):
        requires_approval = True
        reasons.append("Autonomous response (HOTL) is disabled; automated actions need analyst approval.")

    if actor == "agent":
        autonomy = _autonomy(db)
        threshold = _min_confidence(db)
        impact = spec["impact"]
        if autonomy == "recommend_only":
            requires_approval = True
            reasons.append("Agent autonomy is 'recommend_only': every agent action needs analyst approval.")
        elif impact == "high":
            requires_approval = True
            reasons.append(f"{canonical} is a high-impact action; agent requests always need analyst approval.")
        elif confidence is None:
            requires_approval = True
            reasons.append("Agent did not report a confidence; analyst approval required.")
        elif confidence < threshold:
            requires_approval = True
            reasons.append(f"Agent confidence {confidence:.2f} is below the {threshold:.2f} threshold.")
        elif autonomy == "low_impact" and impact != "low":
            requires_approval = True
            reasons.append(f"Agent autonomy is 'low_impact' and {canonical} is {impact} impact.")
        else:
            reasons.append(
                f"Agent autonomy '{autonomy}' permits {impact}-impact {canonical} at confidence {confidence:.2f}."
            )

    if not reasons:
        reasons.append(f"{canonical} on {target or 'the alert'} is permitted for {actor}.")
    return PolicyDecision(True, requires_approval, reasons)
