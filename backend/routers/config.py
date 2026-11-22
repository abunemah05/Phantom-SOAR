"""Integration settings, runtime status and honest connection tests.

Secrets are write-only through the API: reads only say whether one is set and where it comes
from (no characters of the value are ever returned), and an empty value for a secret in an update
keeps what is stored unless `clear` is set. Secret values are encrypted at rest (backend/crypto.py).
"""
import ipaddress
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend import netguard, ratelimit
from backend.crypto import DecryptionError, decrypt_value, is_encrypted, seal_secret
from backend.database import get_db
from backend.dependencies import (
    ADMIN_ROLES,
    SECURITY_ENGINEER_ROLES,
    get_current_user,
    require_admin,
    require_roles,
)
from backend.integrations import llm
from backend.integration_config import (
    DEFAULTS,
    INTEGRATION_KEYS,
    get_bool,
    get_setting,
    hotl_effective,
    hotl_enable_blockers,
    is_configured,
    is_simulation_mode,
    setting_source,
)
from backend.models import SystemConfig, User
from backend.routers.logs import record_log
from backend.schemas import ConfigUpdateRequest, TestConnectionRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/configuration", tags=["Configuration & Integrations"])

CATEGORIES = ("TIP", "SIEM", "IAM", "ITSM", "ORCHESTRATION", "AGENT", "AI")
REMOVED_CATEGORIES = {"EDR", "XDR", "FIREWALL"}  # "AI" is a live category again (OpenRouter triage)

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

BOOL_KEYS = {"hotl_enabled", "simulation_mode", "siem_verify_tls", "require_mfa_for_admin",
             "ai_enabled", "ai_auto_triage", "ai_send_raw_payload"}
URL_KEYS = {"siem_manager_url", "jira_base_url", "jira_webhook_url", "slack_webhook_url"}
# key -> (minimum, maximum, integer?). Out-of-range values are rejected instead of silently ignored.
NUMERIC_KEYS: Dict[str, Tuple[float, float, bool]] = {
    "vt_requests_per_minute": (0, 100000, True),
    "vt_requests_per_day": (0, 10_000_000, True),
    "abuseipdb_daily_limit": (0, 10_000_000, True),
    "nvd_requests_per_30s": (1, 100000, True),
    "tip_max_wait_seconds": (0, 600, False),
    "vt_malicious_weight": (0, 10, False),
    "vt_suspicious_weight": (0, 10, False),
    "vt_malicious_threshold": (0.001, 1, False),
    "vt_min_detections": (0, 1000, False),
    "tip_malicious_threshold": (1, 100, True),
    "tip_suspicious_threshold": (1, 100, True),
    "tip_critical_threshold": (1, 100, True),
    "wazuh_default_block_hours": (0, 720, True),
    "wazuh_default_rate_limit_hours": (0, 720, True),
    "ai_max_alerts_per_minute": (1, 600, True),
}
JIRA_API_VERSIONS = ("2", "3")
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
    """Initial stored value: always empty.

    The database holds only what an administrator saved in the console. Environment variables and the built-in
    defaults are resolved at read time (integration_config.get_setting: database, then environment, then default),
    so changing an environment variable and restarting always takes effect. Freezing them into the database on
    first boot made later environment changes silently ignored.
    """
    return ""


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
        if secret and row.key_value and not is_encrypted(row.key_value):
            row.key_value = seal_secret(row.key_value, True)
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


SECRET_PLACEHOLDER = "••••••••"  # constant: reveals nothing about the value, not even its length or last characters


def _stored_plaintext(row: Optional[SystemConfig]) -> str:
    try:
        return (decrypt_value(row.key_value) or "").strip() if row else ""
    except DecryptionError:
        logger.error(f"Setting {row.key_name} cannot be decrypted with the configured encryption key(s).")
        return ""


def _describe(key: str, row: Optional[SystemConfig]) -> Dict[str, Any]:
    category, env_var = INTEGRATION_KEYS[key]
    stored = _stored_plaintext(row)
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
        "preview": SECRET_PLACEHOLDER if secret and effective else None,
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
    if key in NUMERIC_KEYS:
        low, high, integer = NUMERIC_KEYS[key]
        try:
            number = float(value)
        except ValueError:
            return value, f"{key}: expected a number between {low:g} and {high:g}."
        if number != number or not low <= number <= high or (integer and number != int(number)):
            kind = "whole number" if integer else "number"
            return value, f"{key}: expected a {kind} between {low:g} and {high:g}."
        return str(int(number)) if integer else str(number), None
    if key == "jira_api_version":
        if value not in JIRA_API_VERSIONS:
            return value, f"{key}: expected 2 or 3."
        return value, None
    if key == "agent_min_confidence":
        try:
            number = float(value)
        except ValueError:
            return value, f"{key}: expected a number between 0 and 1."
        if not 0.0 <= number <= 1.0:
            return value, f"{key}: expected a number between 0 and 1."
        return str(number), None
    if key == "openrouter_model":
        if not llm.is_valid_model_slug(value):
            return value, f"{key}: expected a model slug such as vendor/model (see https://openrouter.ai/models)."
        return value, None
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


def _invalidate_integration_caches(updated_keys: List[str]) -> None:
    """Threat-intel verdict caches must not outlive a changed key, threshold or simulation switch."""
    if not updated_keys:
        return
    try:
        from backend.integrations import nvd, tip
        tip.clear_cache()
        nvd.clear_cache()
    except Exception as exc:  # never fail a save because a cache could not be cleared
        logger.warning(f"Could not clear threat-intel caches: {exc}")


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
        if _stored_plaintext(row) == value:
            unchanged.append(key)
            continue
        row.key_value = seal_secret(value, key in SECRET_KEYS)
        row.is_secret = key in SECRET_KEYS
        row.updated_at = _now()
        updated.append(key)
        if key in SECRET_KEYS:
            audit[key] = "cleared" if value == "" else "updated"
        else:
            audit[key] = value
    # Autonomous response can only be switched on while protected assets are listed (same rule as /hotl-toggle).
    # Evaluated with this request's own changes applied, so protected lists and the switch can be saved together.
    if "hotl_enabled" in updated and get_bool("hotl_enabled", db=db):
        blockers = hotl_enable_blockers(db)
        if blockers:
            db.rollback()
            raise HTTPException(status_code=409, detail={"message": "Autonomous response (HOTL) cannot be enabled yet. "
                                                         "Nothing was saved.", "blockers": blockers})
    db.commit()
    _invalidate_integration_caches(updated)

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
        "simulation_source": setting_source("simulation_mode", db=db),
        "nvd_mode": "api_key" if is_configured("nvd_api_key", db=db) else "keyless",
        "hotl_enabled": hotl_effective(db),  # as applied, not the raw switch
        "integrations": {
            "virustotal": is_configured("virustotal_api_key", db=db),
            "abuseipdb": is_configured("abuseipdb_api_key", db=db),
            "otx": is_configured("otx_api_key", db=db),
            "threatfox": is_configured("threatfox_api_key", db=db),
            "nvd": is_configured("nvd_api_key", db=db),  # key saved; NVD also answers keyless (see nvd_mode)
            "wazuh": is_configured("siem_manager_url", "siem_user", "siem_password", db=db),
            "okta": is_configured("okta_domain", "okta_api_token", db=db),
            "jira": is_configured("jira_base_url", "jira_email", "jira_api_token", "jira_project_key", db=db)
            or is_configured("jira_webhook_url", db=db),
            "slack": is_configured("slack_webhook_url", db=db),
            "ai": is_configured("openrouter_api_key", db=db),  # a key exists (does not say AI triage is enabled)
        },
        "agent_autonomy": get_setting("agent_autonomy", db=db),
        "agent_min_confidence": min_confidence,
        "ai_enabled": get_bool("ai_enabled", db=db),
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
    "openrouter": ("AI", "OpenRouter"),
}
_SERVICE_HINTS = (
    ("abuseipdb", "abuseipdb"), ("threatfox", "threatfox"), ("virustotal", "virustotal"),
    ("alienvault", "otx"), ("otx", "otx"), ("nvd", "nvd"), ("wazuh", "wazuh"), ("siem", "wazuh"),
    ("okta", "okta"), ("jira", "jira"), ("slack", "slack"), ("openrouter", "openrouter"),
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
           verify: Union[bool, str] = True, guarded: bool = False, **kwargs) -> Dict[str, Any]:
    """Make one read-only request and classify the outcome without guessing.

    `guarded` (used for any URL that did not come from the stored settings) connects only to public
    addresses, re-checked at connect time (backend/netguard.py).
    """
    display = SERVICES[service][1]
    start = time.monotonic()
    try:
        if guarded:
            client_ctx = httpx.Client(timeout=TEST_TIMEOUT, transport=netguard.guarded_transport(verify=verify),
                                      follow_redirects=False, trust_env=False)
        else:
            client_ctx = httpx.Client(timeout=TEST_TIMEOUT, verify=verify, follow_redirects=False)
        with client_ctx as client:
            response = client.request(method, url, **kwargs)
    except netguard.UnsafeURLError as exc:  # the host resolved to a non-public address when connecting
        return _result(service, ERROR, "Blocked", f"Connection refused by the SSRF guard: {exc}")
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


def _openrouter_ok(response: httpx.Response) -> Optional[bool]:
    if response.status_code != 200:
        return None
    try:
        return isinstance(response.json().get("data"), dict)
    except (ValueError, AttributeError):
        return None


class _EndpointOverride(Exception):
    """The test request cannot be run as asked (reported to the admin as HTTP 400)."""


def _resolve_endpoint(stored: str, override: str, normalise: Callable[[str], str], to_url: Callable[[str], str]) -> Tuple[str, bool]:
    """Pick the URL to test. Returns (value, overridden).

    No override, or an override naming the stored host: the stored value is used. A different host is
    accepted only if it resolves exclusively to public addresses (SSRF guard); the caller must then
    use only credentials supplied in the request, never the stored ones.
    """
    stored_norm = normalise(stored)
    if not override:
        return stored_norm, False
    candidate = normalise(override)
    if not candidate:
        raise _EndpointOverride("endpoint_url is not a valid address for this service.")
    if stored_norm and netguard.same_origin_host(to_url(candidate), to_url(stored_norm)):
        return stored_norm, False
    try:
        netguard.assert_public_url(to_url(candidate))
    except netguard.UnsafeURLError as exc:
        raise _EndpointOverride(f"endpoint_url refused: {exc}")
    return candidate, True


def _test_service(service: str, req: TestConnectionRequest, db: Session) -> Dict[str, Any]:
    display = SERVICES[service][1]
    override_key = (req.api_key or "").strip()
    override_url = (req.endpoint_url or "").strip()
    override_user = (req.username or "").strip()

    def setting(key: str, override: str = "") -> str:
        return override or get_setting(key, db=db)

    def not_configured(what: str) -> Dict[str, Any]:
        return _result(service, NOT_CONFIGURED, "Missing credentials", f"{display} is not configured: set {what}.")

    def endpoint(stored_key: str, normalise: Callable[[str], str], to_url: Callable[[str], str]) -> Tuple[str, bool]:
        return _resolve_endpoint(get_setting(stored_key, db=db), override_url, normalise, to_url)

    def require_own_credentials(*supplied: str) -> None:
        if not all(supplied):
            raise _EndpointOverride(
                "To test a different endpoint, supply the credentials to use for it in the request; "
                "stored credentials are never sent to a host other than the stored one."
            )

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
        keyless = not key
        result = _probe(service, "GET", "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": "CVE-2021-44228"}, headers={} if keyless else {"apiKey": key})
        if keyless:
            if result["status"] == CONNECTED:
                result["message"] = "Connected without an API key (NVD allows 5 requests per 30 s keyless; a free key allows 50)."
            return result
        if result["http_status"] == 404:
            result.update(status=AUTH_FAILED, is_connected=False,
                          message="NVD returned HTTP 404 for a known CVE, which is how it rejects an invalid API key.")
        return result

    if service == "openrouter":
        # One read-only call (GET /api/v1/key, https://openrouter.ai/docs/api-reference/limits): it checks the key and
        # spends no credits. No alert data is sent and the key only ever goes to the vendor's fixed host.
        key = setting("openrouter_api_key", override_key)
        if not key:
            return not_configured("openrouter_api_key")
        result = _probe(service, "GET", f"{llm.OPENROUTER_BASE_URL}{llm.KEY_INFO_PATH}", ok=_openrouter_ok,
                        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"})
        if result["http_status"] == 402:
            result["message"] = "OpenRouter reports insufficient credits for this key (HTTP 402); add credits."
        return result

    if service == "wazuh":
        base, overridden = endpoint("siem_manager_url", lambda v: _http_url(v) or "", lambda v: v)
        if overridden:
            require_own_credentials(override_user, override_key)
            user, password = override_user, override_key
        else:
            user, password = setting("siem_user", override_user), setting("siem_password", override_key)
        if not (base and user and password):
            return not_configured("siem_manager_url (http/https), siem_user and siem_password")
        bundle = (setting("wazuh_ca_bundle", "") or "").strip()
        verify = bundle if bundle and os.path.isfile(bundle) else get_bool("siem_verify_tls", db=db)
        return _probe(service, "POST", f"{base}/security/user/authenticate", auth=(user, password), verify=verify,
                      guarded=overridden)

    if service == "okta":
        host, overridden = endpoint("okta_domain", _host_only, lambda v: f"https://{v}")
        if overridden:
            require_own_credentials(override_key)
            token = override_key
        else:
            token = setting("okta_api_token", override_key)
        if not (host and token):
            return not_configured("okta_domain and okta_api_token")
        if not _HOSTNAME_RE.match(host):
            return _result(service, ERROR, "Invalid domain", f"'{host}' is not a valid Okta domain.")
        return _probe(service, "GET", f"https://{host}/api/v1/users/me",
                      headers={"Authorization": f"SSWS {token}", "Accept": "application/json"}, guarded=overridden)

    if service == "jira":
        base, overridden = endpoint("jira_base_url", lambda v: _http_url(v) or "", lambda v: v)
        if overridden:
            require_own_credentials(override_user, override_key)
            email, token = override_user, override_key
        else:
            email, token = setting("jira_email", override_user), setting("jira_api_token", override_key)
        if base and email and token:
            return _probe(service, "GET", f"{base}/rest/api/2/myself", auth=(email, token),
                          headers={"Accept": "application/json"}, guarded=overridden)
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
    Stored URLs and secrets are used by default. An `api_key` / `username` override is sent only to the
    stored host (or the vendor's fixed API). An `endpoint_url` naming a different host is allowed only if
    it resolves to public addresses, and then the request must carry its own credentials: a stored secret
    is never sent to a host other than the stored one. Rate limited per administrator.
    """
    service = _resolve_service(req.service_name)
    if not service:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown service '{req.service_name}'. Supported: {', '.join(SERVICES)}.",
        )
    ratelimit.enforce("test_connection", f"user:{admin.user_id}")
    try:
        result = _test_service(service, req, db)
    except _EndpointOverride as exc:
        record_log(db, "CONFIG", "WARNING", f"Connection test for {service} refused: {exc}", target=service,
                   details={"by": admin.username, "endpoint_override": True})
        raise HTTPException(status_code=400, detail=str(exc))
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
    return _hotl_payload(hotl_effective(db))


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
    current = hotl_effective(db)  # what is actually applied: a switch set in the environment without protected assets is not "on"
    new_value = (not current) if (payload is None or payload.enabled is None) else bool(payload.enabled)

    row = db.query(SystemConfig).filter(
        SystemConfig.category == "ORCHESTRATION",
        SystemConfig.key_name == "hotl_enabled"
    ).first()
    if row is None:
        row = SystemConfig(category="ORCHESTRATION", key_name="hotl_enabled", is_secret=False)
        db.add(row)
    if new_value and not current:
        blockers = hotl_enable_blockers(db)
        if blockers:
            raise HTTPException(status_code=409, detail={
                "message": "Autonomous response (HOTL) cannot be enabled yet.", "blockers": blockers})
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
