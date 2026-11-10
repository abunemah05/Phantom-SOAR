"""Integration settings, runtime status and honest connection tests.

Secrets are write-only through the API: reads return a masked preview, and an empty
value for a secret in an update keeps what is stored unless `clear` is set.
"""
import ipaddress
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import (
    ADMIN_ROLES,
    SECURITY_ENGINEER_ROLES,
    get_current_user,
    require_admin,
    require_roles,
)
from backend.integration_config import (
    DEFAULTS,
    INTEGRATION_KEYS,
    get_bool,
    get_setting,
    is_configured,
    is_simulation_mode,
)
from backend.models import SystemConfig, User
from backend.routers.logs import record_log
from backend.schemas import ConfigUpdateRequest, TestConnectionRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/configuration", tags=["Configuration & Integrations"])

CATEGORIES = ("TIP", "SIEM", "IAM", "ITSM", "ORCHESTRATION", "AGENT")
REMOVED_CATEGORIES = {"AI", "EDR", "XDR", "FIREWALL"}

SECRET_KEYS = frozenset(
    key for key in INTEGRATION_KEYS
    if key.endswith("_api_key") or key.endswith("_api_token")
    or key in {"siem_password", "slack_webhook_url", "jira_webhook_url"}
)

DEFAULT_CONFIGS: List[Dict[str, Any]] = [
    {
        "category": category,
        "key_name": key,
        "key_value": DEFAULTS.get(key, ""),
        "is_secret": key in SECRET_KEYS,
    }
    for key, (category, _env_var) in INTEGRATION_KEYS.items()
]

# Placeholder credentials shipped by earlier releases; never treat them as configured.
KNOWN_DUMMY_VALUES = {
    "sk-antigravity-live-key-secured",
    "cs-falcon-oauth2-secops-key",
    "cortex-xdr-sec-auth-9942",
    "WazuhSecretPassword123!",
    "vt_api_enterprise_64char_key_placeholder",
    "abuse_ipdb_v2_key_placeholder",
    "alienvault_otx_token_placeholder",
    "fw_panorama_admin_token_active",
    "https://hooks.slack.com/services/SEC/OPS/ALERT",
    "https://wazuh-manager.soc.corp:55000",
    "wazuh-api-admin",
}

BOOL_KEYS = {"hotl_enabled", "simulation_mode", "siem_verify_tls"}
URL_KEYS = {"siem_manager_url", "jira_base_url", "jira_webhook_url", "slack_webhook_url"}
AGENT_AUTONOMY_LEVELS = ("recommend_only", "low_impact", "policy")
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

require_config_viewer = require_roles(
    ADMIN_ROLES | SECURITY_ENGINEER_ROLES,
    "Access denied: integration configuration is restricted to Administrators and Security Engineers.",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _seed_value(key: str) -> str:
    """Initial stored value: an explicit environment value for non-secret keys, else the default."""
    if key not in DEFAULTS:
        return ""
    env_value = os.getenv(INTEGRATION_KEYS[key][1], "").strip()
    return env_value or DEFAULTS[key]


def ensure_default_configurations(db: Session) -> None:
    """Make SystemConfig hold exactly the keys in INTEGRATION_KEYS.

    Rows from removed categories (AI / EDR / XDR / FIREWALL), unknown keys and duplicate rows
    are deleted; missing keys are added; secret flags are corrected; old placeholders are cleared.
    """
    changed = False
    seen = set()
    for row in db.query(SystemConfig).order_by(SystemConfig.config_id.asc()).all():
        category = (row.category or "").upper()
        expected = INTEGRATION_KEYS.get(row.key_name)
        if category in REMOVED_CATEGORIES or not expected or expected[0] != category or row.key_name in seen:
            db.delete(row)
            changed = True
            continue
        seen.add(row.key_name)
        if row.category != category:
            row.category = category
            changed = True
        secret = row.key_name in SECRET_KEYS
        if bool(row.is_secret) != secret:
            row.is_secret = secret
            changed = True
        if (row.key_value or "") in KNOWN_DUMMY_VALUES:
            row.key_value = ""
            changed = True

    for key, (category, _env_var) in INTEGRATION_KEYS.items():
        if key in seen:
            continue
        db.add(SystemConfig(
            category=category,
            key_name=key,
            key_value=_seed_value(key),
            is_secret=key in SECRET_KEYS,
            updated_at=_now(),
        ))
        changed = True

    if changed:
        db.commit()


def _mask(value: str) -> str:
    return "••••" + (value[-4:] if len(value) >= 8 else "")


def _describe(key: str, row: Optional[SystemConfig]) -> Dict[str, Any]:
    category, env_var = INTEGRATION_KEYS[key]
    stored = (row.key_value or "").strip() if row else ""
    env_value = os.getenv(env_var, "").strip()
    if stored:
        source, effective = "database", stored
    elif env_value:
        source, effective = "environment", env_value
    elif DEFAULTS.get(key):
        source, effective = "default", DEFAULTS[key]
    else:
        source, effective = None, ""
    secret = key in SECRET_KEYS
    return {
        "value": "" if secret else effective,
        "is_secret": secret,
        "is_set": bool(effective),
        "preview": _mask(effective) if secret and effective else None,
        "source": source,
        "env_var": env_var,
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
    }


@router.get("")
def get_all_configurations(db: Session = Depends(get_db), user: User = Depends(require_config_viewer)):
    """Integration settings grouped by category. Secret values are never returned, only a masked preview."""
    ensure_default_configurations(db)
    rows = {r.key_name: r for r in db.query(SystemConfig).all()}
    grouped: Dict[str, Dict[str, Any]] = {category: {} for category in CATEGORIES}
    for key, (category, _env_var) in INTEGRATION_KEYS.items():
        grouped.setdefault(category, {})[key] = _describe(key, rows.get(key))
    return grouped


def _validate_value(key: str, value: str) -> Tuple[str, Optional[str]]:
    """Normalise a submitted value; returns (value, error)."""
    if len(value) > 1000:
        return value, f"{key}: value exceeds 1000 characters."
    if value == "":
        return value, None
    if key in BOOL_KEYS:
        lowered = value.lower()
        if lowered in _TRUE:
            return "true", None
        if lowered in _FALSE:
            return "false", None
        return value, f"{key}: expected true or false."
    if key == "agent_min_confidence":
        try:
            number = float(value)
        except ValueError:
            return value, f"{key}: expected a number between 0 and 1."
        if not 0.0 <= number <= 1.0:
            return value, f"{key}: expected a number between 0 and 1."
        return str(number), None
    if key == "agent_autonomy":
        if value not in AGENT_AUTONOMY_LEVELS:
            return value, f"{key}: expected one of {', '.join(AGENT_AUTONOMY_LEVELS)}."
        return value, None
    if key in URL_KEYS:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return value, f"{key}: expected an http(s) URL."
        return value.rstrip("/"), None
    if key == "okta_domain":
        host = _host_only(value)
        if not host or not _HOSTNAME_RE.match(host):
            return value, f"{key}: expected a hostname such as your-org.okta.com."
        return host, None
    if key == "protected_ips":
        items = [i.strip() for i in value.replace("\n", ",").split(",") if i.strip()]
        for item in items:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                return value, f"{key}: '{item}' is not an IP address or CIDR range."
        return ", ".join(items), None
    return value, None


@router.post("")
def update_configurations(
    payload: ConfigUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """[Admin Only] Save settings. All items are validated before anything is written."""
    ensure_default_configurations(db)

    errors: List[str] = []
    writes: List[Tuple[str, str]] = []
    unchanged: List[str] = []
    for item in payload.configs:
        key = item.key_name.strip()
        if key not in INTEGRATION_KEYS:
            errors.append(f"Unknown configuration key '{key}'.")
            continue
        category = INTEGRATION_KEYS[key][0]
        if item.category and item.category.strip().upper() != category:
            errors.append(f"{key} belongs to category {category}, not {item.category.strip().upper()}.")
            continue
        value = (item.key_value or "").strip()
        if item.clear:
            writes.append((key, ""))
            continue
        if key in SECRET_KEYS and value == "":
            unchanged.append(key)
            continue
        value, error = _validate_value(key, value)
        if error:
            errors.append(error)
            continue
        writes.append((key, value))

    if errors:
        raise HTTPException(status_code=400, detail=" ".join(errors))

    rows = {r.key_name: r for r in db.query(SystemConfig).all()}
    updated: List[str] = []
    audit: Dict[str, Any] = {}
    for key, value in writes:
        row = rows.get(key)
        if row is None:
            row = SystemConfig(category=INTEGRATION_KEYS[key][0], key_name=key, key_value="", is_secret=key in SECRET_KEYS)
            db.add(row)
        if (row.key_value or "") == value:
            unchanged.append(key)
            continue
        row.key_value = value
        row.is_secret = key in SECRET_KEYS
        row.updated_at = _now()
        updated.append(key)
        if key in SECRET_KEYS:
            audit[key] = "cleared" if value == "" else "updated"
        else:
            audit[key] = value
    db.commit()

    if updated:
        record_log(db, "CONFIG", "ACTION", f"Admin '{admin.username}' updated settings: {', '.join(updated)}.",
                   target="configuration", details={"changes": audit, "by": admin.username})

    return {
        "status": "Success",
        "message": f"Saved {len(updated)} setting(s)." if updated else "No settings changed.",
        "updated": updated,
        "unchanged": unchanged,
    }


@router.get("/runtime-status")
def get_runtime_status(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Which integrations have credentials, and whether simulation mode / HOTL are on."""
    try:
        min_confidence = float(get_setting("agent_min_confidence", db=db))
    except ValueError:
        min_confidence = float(DEFAULTS["agent_min_confidence"])
    return {
        "simulation_mode": is_simulation_mode(db=db),
        "hotl_enabled": get_bool("hotl_enabled", db=db),
        "integrations": {
            "virustotal": is_configured("virustotal_api_key", db=db),
            "abuseipdb": is_configured("abuseipdb_api_key", db=db),
            "otx": is_configured("otx_api_key", db=db),
            "threatfox": is_configured("threatfox_api_key", db=db),
            "nvd": is_configured("nvd_api_key", db=db),
            "wazuh": is_configured("siem_manager_url", "siem_user", "siem_password", db=db),
            "okta": is_configured("okta_domain", "okta_api_token", db=db),
            "jira": is_configured("jira_base_url", "jira_email", "jira_api_token", "jira_project_key", db=db)
            or is_configured("jira_webhook_url", db=db),
            "slack": is_configured("slack_webhook_url", db=db),
        },
        "agent_autonomy": get_setting("agent_autonomy", db=db),
        "agent_min_confidence": min_confidence,
    }


# --- Connection tests ------------------------------------------------------------
SERVICES: Dict[str, Tuple[str, str]] = {
    "virustotal": ("TIP", "VirusTotal"),
    "abuseipdb": ("TIP", "AbuseIPDB"),
    "otx": ("TIP", "AlienVault OTX"),
    "threatfox": ("TIP", "ThreatFox"),
    "nvd": ("TIP", "NIST NVD"),
    "wazuh": ("SIEM", "Wazuh Manager API"),
    "okta": ("IAM", "Okta"),
    "jira": ("ITSM", "Jira"),
    "slack": ("ITSM", "Slack"),
}
_SERVICE_HINTS = (
    ("abuseipdb", "abuseipdb"), ("threatfox", "threatfox"), ("virustotal", "virustotal"),
    ("alienvault", "otx"), ("otx", "otx"), ("nvd", "nvd"), ("wazuh", "wazuh"), ("siem", "wazuh"),
    ("okta", "okta"), ("jira", "jira"), ("slack", "slack"),
)
TEST_TIMEOUT = httpx.Timeout(6.0, connect=4.0)

NOT_CONFIGURED = "Not Configured"
CONNECTED = "Connected"
AUTH_FAILED = "Auth failed"
UNREACHABLE = "Unreachable"
ERROR = "Error"
NOT_TESTED = "Configured (not tested to avoid posting)"


def _resolve_service(name: str) -> Optional[str]:
    normalized = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    if normalized in SERVICES:
        return normalized
    for hint, service in _SERVICE_HINTS:
        if hint in normalized:
            return service
    return None


def _host_only(value: str) -> str:
    value = (value or "").strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").lower()


def _http_url(value: str) -> Optional[str]:
    parsed = urlparse((value or "").strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return value.strip().rstrip("/")


def _result(service: str, status: str, health: str, message: str,
            latency_ms: Optional[int] = None, http_status: Optional[int] = None) -> Dict[str, Any]:
    category, display = SERVICES[service]
    return {
        "service": service,
        "service_name": display,
        "category": category,
        "status": status,
        "is_connected": status == CONNECTED,
        "health": health,
        "message": message,
        "latency_ms": latency_ms,
        "http_status": http_status,
        "tested_at": _now().isoformat(),
    }


def _probe(service: str, method: str, url: str, ok: Optional[Callable[[httpx.Response], Optional[bool]]] = None,
           verify: bool = True, **kwargs) -> Dict[str, Any]:
    """Make one read-only request and classify the outcome without guessing."""
    display = SERVICES[service][1]
    start = time.monotonic()
    try:
        with httpx.Client(timeout=TEST_TIMEOUT, verify=verify, follow_redirects=False) as client:
            response = client.request(method, url, **kwargs)
    except httpx.TimeoutException:
        latency = int((time.monotonic() - start) * 1000)
        return _result(service, UNREACHABLE, "Timed out", f"{display} did not answer within {TEST_TIMEOUT.read:.0f}s.", latency)
    except httpx.HTTPError as exc:
        latency = int((time.monotonic() - start) * 1000)
        return _result(service, UNREACHABLE, "Connection error", f"Could not reach {display}: {exc.__class__.__name__}: {exc}", latency)
    latency = max(1, int((time.monotonic() - start) * 1000))
    code = response.status_code

    verdict = ok(response) if ok else (code == 200)
    if verdict:
        return _result(service, CONNECTED, f"HTTP {code}", f"{display} accepted the credentials.", latency, code)
    if code in (401, 403) or (verdict is False and code == 200):
        return _result(service, AUTH_FAILED, f"HTTP {code}", f"{display} rejected the credentials.", latency, code)
    if code == 429:
        return _result(service, ERROR, "HTTP 429", f"{display} is rate limiting this key (HTTP 429); credentials could not be confirmed.", latency, code)
    return _result(service, ERROR, f"HTTP {code}", f"{display} answered HTTP {code}; credentials could not be confirmed.", latency, code)


def _threatfox_ok(response: httpx.Response) -> Optional[bool]:
    if response.status_code != 200:
        return None
    try:
        query_status = str(response.json().get("query_status", ""))
    except ValueError:
        return None
    if query_status in ("ok", "no_result"):
        return True
    return False if "auth" in query_status.lower() else None


def _test_service(service: str, req: TestConnectionRequest, db: Session) -> Dict[str, Any]:
    display = SERVICES[service][1]
    override_key = (req.api_key or "").strip()
    override_url = (req.endpoint_url or "").strip()
    override_user = (req.username or "").strip()

    def setting(key: str, override: str = "") -> str:
        return override or get_setting(key, db=db)

    def not_configured(what: str) -> Dict[str, Any]:
        return _result(service, NOT_CONFIGURED, "Missing credentials", f"{display} is not configured: set {what}.")

    if service == "virustotal":
        key = setting("virustotal_api_key", override_key)
        if not key:
            return not_configured("virustotal_api_key")
        return _probe(service, "GET", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": key})

    if service == "abuseipdb":
        key = setting("abuseipdb_api_key", override_key)
        if not key:
            return not_configured("abuseipdb_api_key")
        return _probe(service, "GET", "https://api.abuseipdb.com/api/v2/check",
                      params={"ipAddress": "127.0.0.1"}, headers={"Key": key, "Accept": "application/json"})

    if service == "otx":
        key = setting("otx_api_key", override_key)
        if not key:
            return not_configured("otx_api_key")
        return _probe(service, "GET", "https://otx.alienvault.com/api/v1/users/me", headers={"X-OTX-API-KEY": key})

    if service == "threatfox":
        key = setting("threatfox_api_key", override_key)
        if not key:
            return not_configured("threatfox_api_key")
        return _probe(service, "POST", "https://threatfox-api.abuse.ch/api/v1/", ok=_threatfox_ok,
                      json={"query": "get_iocs", "days": 1}, headers={"Auth-Key": key})

    if service == "nvd":
        key = setting("nvd_api_key", override_key)
        if not key:
            return _result(service, NOT_CONFIGURED, "No API key",
                           "No NVD API key is set. NVD can still be queried without one at a much lower rate limit.")
        result = _probe(service, "GET", "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": "CVE-2021-44228"}, headers={"apiKey": key})
        if result["http_status"] == 404:
            result.update(status=AUTH_FAILED, is_connected=False,
                          message="NVD returned HTTP 404 for a known CVE, which is how it rejects an invalid API key.")
        return result

    if service == "wazuh":
        base = _http_url(setting("siem_manager_url", override_url))
        user = setting("siem_user", override_user)
        password = setting("siem_password", override_key)
        if not (base and user and password):
            return not_configured("siem_manager_url (http/https), siem_user and siem_password")
        verify = get_bool("siem_verify_tls", db=db)
        return _probe(service, "POST", f"{base}/security/user/authenticate", auth=(user, password), verify=verify)

    if service == "okta":
        host = _host_only(setting("okta_domain", override_url))
        token = setting("okta_api_token", override_key)
        if not (host and token):
            return not_configured("okta_domain and okta_api_token")
        if not _HOSTNAME_RE.match(host):
            return _result(service, ERROR, "Invalid domain", f"'{host}' is not a valid Okta domain.")
        return _probe(service, "GET", f"https://{host}/api/v1/users/me",
                      headers={"Authorization": f"SSWS {token}", "Accept": "application/json"})

    if service == "jira":
        base = _http_url(setting("jira_base_url", override_url))
        email = setting("jira_email", override_user)
        token = setting("jira_api_token", override_key)
        if base and email and token:
            return _probe(service, "GET", f"{base}/rest/api/2/myself", auth=(email, token),
                          headers={"Accept": "application/json"})
        if get_setting("jira_webhook_url", db=db):
            return _result(service, NOT_TESTED, "Webhook configured",
                           "A Jira automation webhook is configured. It is not called by this test because every call creates an issue.")
        return not_configured("jira_base_url, jira_email and jira_api_token (or jira_webhook_url)")

    if service == "slack":
        if override_url or override_key or get_setting("slack_webhook_url", db=db):
            return _result(service, NOT_TESTED, "Webhook configured",
                           "A Slack incoming webhook is configured. It is not called by this test because every call posts a message.")
        return not_configured("slack_webhook_url")

    raise HTTPException(status_code=400, detail=f"Unknown service '{req.service_name}'.")


@router.post("/test-connection")
def test_integration_connection(
    req: TestConnectionRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    [Admin Only] Perform a real, read-only authentication check against one integration and report
    exactly what happened: Not Configured / Connected / Auth failed / Unreachable / Error, or
    "Configured (not tested to avoid posting)" for webhooks that cannot be called without side effects.
    Stored settings are used unless api_key / endpoint_url / username overrides are supplied.
    """
    service = _resolve_service(req.service_name)
    if not service:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown service '{req.service_name}'. Supported: {', '.join(SERVICES)}.",
        )
    result = _test_service(service, req, db)
    record_log(db, "CONFIG", "INFO" if result["is_connected"] else "WARNING",
               f"Connection test for {result['service_name']}: {result['status']}.",
               target=service, details={"by": admin.username, "health": result["health"], "http_status": result["http_status"]})
    return result


# --- HOTL kill switch ------------------------------------------------------------
class HotlToggleRequest(BaseModel):
    enabled: Optional[bool] = None


def _hotl_payload(enabled: bool) -> Dict[str, Any]:
    return {
        "hotl_enabled": enabled,
        "mode": "Autonomous Containment (HOTL)" if enabled else "Manual Review Standby (HITL Only)",
        "status": "Online" if enabled else "Paused",
    }


@router.get("/hotl-status")
def get_hotl_status(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Current state of the autonomous containment (HOTL) kill switch."""
    return _hotl_payload(get_bool("hotl_enabled", db=db))


@router.post("/hotl-toggle")
def toggle_hotl_status(
    payload: Optional[HotlToggleRequest] = None,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    [Admin Only] Toggle or set the HOTL engine. While paused, every alert waits for analyst approval.
    """
    ensure_default_configurations(db)
    current = get_bool("hotl_enabled", db=db)
    new_value = (not current) if (payload is None or payload.enabled is None) else bool(payload.enabled)

    row = db.query(SystemConfig).filter(
        SystemConfig.category == "ORCHESTRATION",
        SystemConfig.key_name == "hotl_enabled"
    ).first()
    if row is None:
        row = SystemConfig(category="ORCHESTRATION", key_name="hotl_enabled", is_secret=False)
        db.add(row)
    row.key_value = "true" if new_value else "false"
    row.updated_at = _now()
    db.commit()

    record_log(
        db, "SOAR_CORE", "ACTION" if new_value else "WARNING",
        f"Admin '{admin.username}' set the HOTL engine to "
        f"{'ONLINE (Autonomous Containment)' if new_value else 'PAUSED (Standby - HITL Enforced)'}.",
        target="ORCHESTRATION_CORE",
        details={"hotl_enabled": new_value, "by": admin.username},
    )

    return {
        **_hotl_payload(new_value),
        "message": f"HOTL Engine {'activated' if new_value else 'paused in Standby mode'}.",
    }
