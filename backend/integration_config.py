"""Single source of truth for integration and orchestration settings.

Values saved from the Configuration page (SystemConfig rows) win; environment
variables are the fallback so Docker / CI deployments work without the UI.
An empty value in the database counts as "not set" and falls through to the
environment, then to DEFAULTS.
"""
import concurrent.futures
import ipaddress
import logging
import os
import socket
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import SystemConfig

logger = logging.getLogger(__name__)

# key_name -> (SystemConfig category, environment variable)
INTEGRATION_KEYS: Dict[str, Tuple[str, str]] = {
    # Threat intelligence
    "virustotal_api_key": ("TIP", "VIRUSTOTAL_API_KEY"),
    "abuseipdb_api_key": ("TIP", "ABUSEIPDB_API_KEY"),
    "otx_api_key": ("TIP", "ALIENVAULT_OTX_API_KEY"),
    "threatfox_api_key": ("TIP", "THREATFOX_API_KEY"),
    "nvd_api_key": ("TIP", "NVD_API_KEY"),
    # Wazuh manager API (used for ingestion context and active response)
    "siem_manager_url": ("SIEM", "WAZUH_API_URL"),
    "siem_user": ("SIEM", "WAZUH_API_USER"),
    "siem_password": ("SIEM", "WAZUH_API_PASSWORD"),
    "siem_verify_tls": ("SIEM", "WAZUH_VERIFY_TLS"),
    # Threat-intel tuning (empty = built-in default; see backend/integrations/tip.py and nvd.py)
    "vt_requests_per_minute": ("TIP", "VT_REQUESTS_PER_MINUTE"),
    "vt_requests_per_day": ("TIP", "VT_REQUESTS_PER_DAY"),
    "abuseipdb_daily_limit": ("TIP", "ABUSEIPDB_DAILY_LIMIT"),
    "nvd_requests_per_30s": ("TIP", "NVD_REQUESTS_PER_30S"),
    "tip_max_wait_seconds": ("TIP", "TIP_MAX_WAIT_SECONDS"),
    "vt_malicious_weight": ("TIP", "VT_MALICIOUS_WEIGHT"),
    "vt_suspicious_weight": ("TIP", "VT_SUSPICIOUS_WEIGHT"),
    "vt_malicious_threshold": ("TIP", "VT_MALICIOUS_THRESHOLD"),
    "vt_min_detections": ("TIP", "VT_MIN_DETECTIONS"),
    "tip_malicious_threshold": ("TIP", "TIP_MALICIOUS_THRESHOLD"),
    "tip_suspicious_threshold": ("TIP", "TIP_SUSPICIOUS_THRESHOLD"),
    "tip_critical_threshold": ("TIP", "TIP_CRITICAL_THRESHOLD"),
    # Wazuh active response (see wazuh/README.md)
    "wazuh_ca_bundle": ("SIEM", "WAZUH_CA_BUNDLE"),
    "wazuh_ar_script_prefix": ("SIEM", "WAZUH_AR_SCRIPT_PREFIX"),
    "wazuh_windows_agent_ids": ("SIEM", "WAZUH_WINDOWS_AGENT_IDS"),
    "wazuh_firewall_agent_ids": ("SIEM", "WAZUH_FIREWALL_AGENT_IDS"),
    "wazuh_default_block_hours": ("SIEM", "WAZUH_DEFAULT_BLOCK_HOURS"),
    "wazuh_default_rate_limit_hours": ("SIEM", "WAZUH_DEFAULT_RATE_LIMIT_HOURS"),
    "wazuh_ar_block_command": ("SIEM", "WAZUH_AR_BLOCK_COMMAND"),
    "wazuh_ar_unblock_command": ("SIEM", "WAZUH_AR_UNBLOCK_COMMAND"),
    "wazuh_ar_isolate_command": ("SIEM", "WAZUH_AR_ISOLATE_COMMAND"),
    "wazuh_ar_unisolate_command": ("SIEM", "WAZUH_AR_UNISOLATE_COMMAND"),
    "wazuh_ar_kill_command": ("SIEM", "WAZUH_AR_KILL_COMMAND"),
    "wazuh_ar_quarantine_command": ("SIEM", "WAZUH_AR_QUARANTINE_COMMAND"),
    "wazuh_ar_rate_limit_command": ("SIEM", "WAZUH_AR_RATE_LIMIT_COMMAND"),
    # Identity provider
    "okta_domain": ("IAM", "OKTA_DOMAIN"),
    "okta_login_domain": ("IAM", "OKTA_LOGIN_DOMAIN"),
    "okta_api_token": ("IAM", "OKTA_API_TOKEN"),
    # ITSM / notifications
    "jira_base_url": ("ITSM", "JIRA_BASE_URL"),
    "jira_email": ("ITSM", "JIRA_EMAIL"),
    "jira_api_token": ("ITSM", "JIRA_API_TOKEN"),
    "jira_project_key": ("ITSM", "JIRA_PROJECT_KEY"),
    "jira_webhook_url": ("ITSM", "JIRA_WEBHOOK_URL"),
    "jira_api_version": ("ITSM", "JIRA_API_VERSION"),
    "jira_issue_type": ("ITSM", "JIRA_ISSUE_TYPE"),
    "slack_webhook_url": ("ITSM", "SLACK_WEBHOOK_URL"),
    # Orchestration guardrails
    "hotl_enabled": ("ORCHESTRATION", "PHANTOM_HOTL_ENABLED"),
    "simulation_mode": ("ORCHESTRATION", "PHANTOM_SIMULATION_MODE"),
    "protected_hosts": ("ORCHESTRATION", "PHANTOM_PROTECTED_HOSTS"),
    "protected_users": ("ORCHESTRATION", "PHANTOM_PROTECTED_USERS"),
    "protected_ips": ("ORCHESTRATION", "PHANTOM_PROTECTED_IPS"),
    # Built-in AI triage (OpenRouter). Off by default; see backend/engine/ai_triage.py.
    "openrouter_api_key": ("AI", "OPENROUTER_API_KEY"),
    "openrouter_model": ("AI", "OPENROUTER_MODEL"),
    "ai_enabled": ("AI", "PHANTOM_AI_ENABLED"),
    "ai_auto_triage": ("AI", "PHANTOM_AI_AUTO_TRIAGE"),
    "ai_max_alerts_per_minute": ("AI", "PHANTOM_AI_MAX_ALERTS_PER_MINUTE"),
    "ai_send_raw_payload": ("AI", "PHANTOM_AI_SEND_RAW_PAYLOAD"),
    # AI agent guardrails
    "agent_min_confidence": ("AGENT", "PHANTOM_AGENT_MIN_CONFIDENCE"),
    "agent_autonomy": ("AGENT", "PHANTOM_AGENT_AUTONOMY"),  # recommend_only | low_impact | policy
    # Explicit operator acknowledgement that simulation mode is intended in a production environment
    # even though real connectors are configured (see production_safety_errors).
    "simulation_confirmed_in_production": ("ORCHESTRATION", "PHANTOM_SIMULATION_CONFIRMED_IN_PRODUCTION"),
    # Administrators must have MFA enabled to sign in (enforced by backend/security.py).
    "require_mfa_for_admin": ("ORCHESTRATION", "PHANTOM_REQUIRE_MFA_FOR_ADMIN"),
}

DEFAULTS: Dict[str, str] = {
    # Autonomous response is OFF until an operator enables it (after listing protected assets).
    "hotl_enabled": "false",
    # Simulation is the safe default: nothing is sent to a real system until it is turned off.
    "simulation_mode": "true",
    "simulation_confirmed_in_production": "false",
    "siem_verify_tls": "true",
    "agent_min_confidence": "0.85",
    "agent_autonomy": "recommend_only",
    # AI triage is opt-in: nothing is sent to a model until an operator enables it and adds a key.
    "openrouter_model": "openai/gpt-6.1-terra",  # = backend.integrations.llm.DEFAULT_MODEL (kept in sync by a test)
    "ai_enabled": "false",
    "ai_auto_triage": "false",
    "ai_max_alerts_per_minute": "10",
    "ai_send_raw_payload": "false",
}

_TRUE = {"1", "true", "yes", "on"}


def _read_db_value(db: Session, category: str, key_name: str) -> Optional[str]:
    row = (
        db.query(SystemConfig)
        .filter(SystemConfig.category == category, SystemConfig.key_name == key_name)
        .first()
    )
    if not row:
        return None
    # Secret values are stored as "enc:v1:..." (backend/crypto.py); legacy plaintext passes through.
    try:
        from backend.crypto import decrypt_value
        return decrypt_value(row.key_value)
    except Exception as exc:  # undecryptable (wrong key): treat as unset rather than crash every caller
        logger.error(f"Setting {key_name} cannot be decrypted: {exc}")
        return None


def get_setting(key_name: str, db: Optional[Session] = None, default: Optional[str] = None) -> str:
    """Resolve a setting: database value, then environment variable, then default."""
    category, env_var = INTEGRATION_KEYS.get(key_name, ("", key_name.upper()))

    value: Optional[str] = None
    if category:
        own_session = db is None
        session = SessionLocal() if own_session else db
        try:
            value = _read_db_value(session, category, key_name)
        except Exception as e:  # table missing during bootstrap, DB unavailable, ...
            logger.debug(f"Config lookup for {key_name} failed: {e}")
        finally:
            if own_session:
                session.close()

    if value is None or str(value).strip() == "":
        value = os.getenv(env_var, "")
    if str(value).strip() == "":
        value = default if default is not None else DEFAULTS.get(key_name, "")
    return str(value).strip()


def setting_source(key_name: str, db: Optional[Session] = None) -> Optional[str]:
    """Where a setting's effective value comes from: "database", "environment", "default" or None (not set).
    Never returns the value itself, so it is safe for status endpoints."""
    category, env_var = INTEGRATION_KEYS.get(key_name, ("", key_name.upper()))
    if category:
        own_session = db is None
        session = SessionLocal() if own_session else db
        try:
            stored = _read_db_value(session, category, key_name)
        except Exception:
            stored = None
        finally:
            if own_session:
                session.close()
        if stored is not None and str(stored).strip():
            return "database"
    if os.getenv(env_var, "").strip():
        return "environment"
    return "default" if DEFAULTS.get(key_name) else None


def get_bool(key_name: str, db: Optional[Session] = None) -> bool:
    return get_setting(key_name, db=db).lower() in _TRUE


def get_list(key_name: str, db: Optional[Session] = None) -> List[str]:
    """Comma- or newline-separated setting as a list of non-empty, stripped items."""
    raw = get_setting(key_name, db=db).replace("\n", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def is_configured(*key_names: str, db: Optional[Session] = None) -> bool:
    """True when every named setting has a non-empty value."""
    return all(get_setting(k, db=db) for k in key_names)


def is_simulation_mode(db: Optional[Session] = None) -> bool:
    """Simulation mode lets unconfigured connectors record clearly-labelled simulated actions."""
    return get_bool("simulation_mode", db=db)


# --- Safety helpers: production checks and protected assets -------------------
# (WS1: defaults, helpers and validation. Appended below the settings read path.)

# Connector groups whose configuration means "this deployment talks to real systems".
_REAL_CONNECTORS: Dict[str, Tuple[str, ...]] = {
    "Wazuh manager": ("siem_manager_url", "siem_user", "siem_password"),
    "Okta": ("okta_domain", "okta_api_token"),
    "Jira": ("jira_base_url", "jira_email", "jira_api_token"),
    "Jira webhook": ("jira_webhook_url",),
    "Slack": ("slack_webhook_url",),
    "VirusTotal": ("virustotal_api_key",),
    "AbuseIPDB": ("abuseipdb_api_key",),
    "AlienVault OTX": ("otx_api_key",),
    "ThreatFox": ("threatfox_api_key",),
    "NVD": ("nvd_api_key",),
}

AUTO_PROTECT_CACHE_SECONDS = 300
_RESOLVE_TIMEOUT_SECONDS = 2.0
_auto_cache: Dict[str, Tuple[float, object]] = {}


def is_production() -> bool:
    return os.getenv("PHANTOM_ENV", "development").strip().lower() in ("production", "prod")


def configured_real_connectors(db: Optional[Session] = None) -> List[str]:
    """Names of connectors / threat-intel providers that have real credentials configured."""
    return [name for name, keys in _REAL_CONNECTORS.items() if is_configured(*keys, db=db)]


def production_safety_errors(db: Optional[Session] = None) -> List[str]:
    """Reasons this deployment must not start as configured. Empty list means no problem found.

    In production, simulation mode on while any real connector or threat-intel key is configured is a
    contradictory setup: response actions are only rehearsed and lab-fixture threat intel is accepted next to
    live credentials. Fix it with PHANTOM_SIMULATION_MODE=false (or the console), or confirm it is intended with
    PHANTOM_SIMULATION_CONFIRMED_IN_PRODUCTION=true; environment changes take effect on the next start. It is refused unless the operator sets
    simulation_confirmed_in_production=true to say it is intended.
    """
    if not is_production():
        return []
    errors: List[str] = []
    if is_simulation_mode(db) and not get_bool("simulation_confirmed_in_production", db=db):
        real = configured_real_connectors(db)
        if real:
            errors.append(
                "PHANTOM_ENV=production with simulation mode ON while real connectors are configured ("
                + ", ".join(real)
                + "). Turn simulation_mode off, or set simulation_confirmed_in_production=true "
                "if simulation is intended."
            )
    return errors


def _entry_is_ip(entry: str) -> bool:
    try:
        ipaddress.ip_network(entry.strip(), strict=False)
        return True
    except ValueError:
        return False


def validate_protected_list(key_name: str, raw: str) -> List[str]:
    """Errors for a protected_hosts / protected_users / protected_ips value (empty list when valid)."""
    items = [i.strip() for i in str(raw or "").replace("\n", ",").split(",") if i.strip()]
    errors: List[str] = []
    for item in items:
        if key_name == "protected_ips" and not _entry_is_ip(item):
            errors.append(f"'{item}' is not a valid IP address or CIDR network.")
        elif key_name in ("protected_hosts", "protected_users") and any(c in item for c in " \t;"):
            errors.append(f"'{item}' contains whitespace or ';'; separate entries with commas.")
    return errors


def _cached(key: str, factory):
    now = time.monotonic()
    hit = _auto_cache.get(key)
    if hit and now - hit[0] < AUTO_PROTECT_CACHE_SECONDS:
        return hit[1]
    try:
        value = factory()
    except Exception as exc:  # best effort: never raise from auto-protection discovery
        logger.debug(f"auto-protect discovery '{key}' failed: {exc}")
        value = ([], []) if key == "system" else []
    _auto_cache[key] = (now, value)
    return value


def clear_auto_protect_cache() -> None:
    _auto_cache.clear()


def _resolve_host(name: str) -> List[str]:
    """Addresses for a hostname with a hard timeout; [] on failure (DNS must never stall policy)."""
    def lookup() -> List[str]:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None)})

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(lookup).result(timeout=_RESOLVE_TIMEOUT_SECONDS)
    except Exception:
        return []
    finally:
        pool.shutdown(wait=False)


def _default_gateway(route_file: str = "/proc/net/route") -> Optional[str]:
    """IPv4 default gateway from /proc/net/route (Linux); None elsewhere or on any error."""
    try:
        with open(route_file) as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                    return str(ipaddress.ip_address(int(fields[2], 16).to_bytes(4, "little")))
    except Exception:
        return None
    return None


def _system_identity() -> Tuple[List[str], List[str]]:
    """(hostnames, ips) of this server: hostname, FQDN, local addresses, outbound address, default gateway."""
    hosts = {"localhost"}
    ips = {"127.0.0.0/8", "::1"}
    try:
        name = socket.gethostname()
        if name:
            hosts.add(name.lower())
            hosts.add(name.split(".")[0].lower())
    except Exception:
        pass
    try:
        fqdn = socket.getfqdn()
        if fqdn:
            hosts.add(fqdn.lower())
    except Exception:
        pass
    for name in list(hosts):
        if name != "localhost":
            ips.update(_resolve_host(name))
    try:  # primary outbound address; a UDP connect sends no packets
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))
            ips.add(sock.getsockname()[0])
    except Exception:
        pass
    gateway = _default_gateway()
    if gateway:
        ips.add(gateway)
    ips.discard("0.0.0.0")
    return sorted(hosts), sorted(ips)


def _manager_endpoint(db: Optional[Session]) -> Tuple[List[str], List[str]]:
    """(hosts, ips) of the Wazuh manager parsed from siem_manager_url."""
    url = get_setting("siem_manager_url", db=db)
    if not url:
        return [], []
    parsed = urlparse(url if "//" in url else f"//{url}")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return [], []
    if _entry_is_ip(host):
        return [], [host]
    resolved = _cached(f"resolve:{host}", lambda: _resolve_host(host))
    return [host], list(resolved)


def automatic_protected(db: Optional[Session] = None) -> Dict[str, List[str]]:
    """Protected entries that need no configuration: the Wazuh manager, loopback, this server, the gateway.

    Best effort and never raises. Keys: hosts, ips (users have no automatic entries).
    """
    sys_hosts, sys_ips = _cached("system", _system_identity)
    mgr_hosts, mgr_ips = _manager_endpoint(db)
    return {
        "hosts": sorted({*sys_hosts, *mgr_hosts}),
        "ips": sorted({*sys_ips, *mgr_ips}),
    }


def effective_protected(db: Optional[Session] = None) -> Dict[str, List[str]]:
    """Configured protected_hosts/users/ips plus the automatic entries. Policy enforces these lists."""
    auto = automatic_protected(db)
    hosts = get_list("protected_hosts", db=db)
    ips = get_list("protected_ips", db=db)
    return {
        "hosts": _unique_ci(hosts + auto["hosts"]),
        "ips": _unique_ci(ips + auto["ips"]),
        "users": _unique_ci(get_list("protected_users", db=db)),
        "auto_hosts": auto["hosts"],
        "auto_ips": auto["ips"],
    }


def _unique_ci(items: List[str]) -> List[str]:
    seen, out = set(), []
    for item in items:
        if item.lower() not in seen:
            seen.add(item.lower())
            out.append(item)
    return out


def hotl_enable_blockers(db: Optional[Session] = None) -> List[str]:
    """Reasons autonomous response (HOTL) must not be switched on yet; empty when it may be enabled.

    Automatic entries (loopback, this server, the gateway) always exist, so they do not
    count: the operator must have named protected assets, or have configured the Wazuh
    manager so it is protected automatically, and must have listed protected users.
    """
    blockers: List[str] = []
    mgr_hosts, mgr_ips = _manager_endpoint(db)
    if get_setting("siem_manager_url", db=db) and not (mgr_hosts or mgr_ips):
        blockers.append("siem_manager_url is set but its host cannot be parsed, so the Wazuh manager cannot be protected.")
    if not (get_list("protected_hosts", db=db) or get_list("protected_ips", db=db) or mgr_hosts or mgr_ips):
        blockers.append(
            "No protected hosts or IPs: list your Wazuh manager, gateways, DNS and domain controllers "
            "in protected_hosts / protected_ips (or configure siem_manager_url)."
        )
    if not get_list("protected_users", db=db):
        blockers.append("No protected users: list break-glass admins and service accounts in protected_users.")
    for key in ("protected_hosts", "protected_users", "protected_ips"):
        blockers.extend(f"{key}: {e}" for e in validate_protected_list(key, get_setting(key, db=db)))
    return blockers


def hotl_effective(db: Optional[Session] = None) -> bool:
    """Autonomous response (HOTL) as it is actually applied: switched on AND allowed to be on.

    The switch can be set from the environment (PHANTOM_HOTL_ENABLED) without going through the console's
    checks, so the protected-asset requirements are enforced here, at run time, for every reader: HOTL with
    no protected hosts/IPs/users listed never runs, whatever the switch says.
    """
    if not get_bool("hotl_enabled", db=db):
        return False
    blockers = hotl_enable_blockers(db)
    if blockers:
        logger.warning("HOTL is switched on but ignored until these are fixed: %s", "; ".join(blockers))
        return False
    return True
