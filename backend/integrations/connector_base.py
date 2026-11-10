"""Shared plumbing for the response connectors (EDR, firewall, IAM, ITSM).

Every connector call returns the same result shape, and never claims an
outcome that did not happen:

    {
        "status": "Success" | "Simulated" | "Skipped" | "Failed",
        "execution_mode": "live" | "simulated" | "skipped" | "failed",
        "action": str, "target": str | None, "provider": str,
        "details": {...},            # provider response, or why nothing ran
        "error": str | None,
        "timestamp": iso-8601 UTC,
    }

"live" means a real API call was made and accepted. "simulated" means the
connector is not configured and simulation mode is on, so nothing was sent.
"skipped" means not configured and simulation mode is off. "failed" means the
call was attempted (or could not be attempted) and did not succeed.

Settings are read at call time through integration_config so values saved on
the Configuration page take effect immediately.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import httpx

from backend import integration_config
from backend.database import SessionLocal

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = httpx.Timeout(8.0, connect=4.0)

STATUS_BY_MODE = {
    "live": "Success",
    "simulated": "Simulated",
    "skipped": "Skipped",
    "failed": "Failed",
}

_TRUE = {"1", "true", "yes", "on"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def http_client(verify: bool = True) -> httpx.Client:
    """Factory for outbound HTTP clients (tests replace it with a MockTransport client)."""
    return httpx.Client(timeout=HTTP_TIMEOUT, verify=verify)


def read_settings(*keys: str) -> Dict[str, str]:
    """Resolve several integration settings with one database session."""
    db = SessionLocal()
    try:
        return {key: integration_config.get_setting(key, db=db) for key in keys}
    finally:
        db.close()


def as_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in _TRUE


def missing_settings(settings: Dict[str, str], required: Iterable[str]) -> List[str]:
    return [key for key in required if not settings.get(key)]


def make_result(
    action: str,
    target: Optional[str],
    provider: str,
    mode: str,
    details: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    result = {
        "status": STATUS_BY_MODE[mode],
        "execution_mode": mode,
        "action": action,
        "target": target,
        "provider": provider,
        "details": details or {},
        "error": error,
        "timestamp": now_iso(),
    }
    result.update(extra)
    return result


def live(action: str, target: Optional[str], provider: str, details: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    return make_result(action, target, provider, "live", details, **extra)


def failed(
    action: str,
    target: Optional[str],
    provider: str,
    error: str,
    details: Optional[Dict[str, Any]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    payload = dict(details or {})
    payload.setdefault("error", error)
    logger.warning(f"[{provider}] {action} on {target} failed: {error}")
    return make_result(action, target, provider, "failed", payload, error=error, **extra)


def unconfigured(
    action: str,
    target: Optional[str],
    provider: str,
    missing: List[str],
    **extra: Any,
) -> Dict[str, Any]:
    """Result for a connector whose settings are incomplete: simulated or skipped, never 'Success'."""
    missing_text = ", ".join(missing)
    if integration_config.is_simulation_mode():
        details = {
            "simulated": True,
            "message": (
                f"SIMULATED: {provider} is not configured (missing: {missing_text}). "
                "No request was sent and nothing was changed."
            ),
            "missing_settings": missing,
        }
        logger.info(f"[{provider}] SIMULATED {action} on {target} (connector not configured).")
        return make_result(action, target, provider, "simulated", details, **extra)

    details = {
        "message": (
            f"Skipped: {provider} is not configured (missing: {missing_text}) "
            "and simulation mode is off."
        ),
        "missing_settings": missing,
    }
    logger.info(f"[{provider}] Skipped {action} on {target} (connector not configured, simulation off).")
    return make_result(action, target, provider, "skipped", details, **extra)


def describe_http_error(exc: Exception) -> str:
    """Short, secret-free description of an outbound HTTP failure."""
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "").strip().replace("\n", " ")
        return f"HTTP {exc.response.status_code} from {exc.request.url.host}: {body[:300]}"
    if isinstance(exc, httpx.TimeoutException):
        return f"Timed out contacting {_host_of(exc)}"
    if isinstance(exc, httpx.ConnectError):
        return f"Unreachable: could not connect to {_host_of(exc)}"
    if isinstance(exc, httpx.HTTPError):
        return f"HTTP error contacting {_host_of(exc)}: {exc.__class__.__name__}"
    return f"{exc.__class__.__name__}: {exc}"


def _host_of(exc: httpx.HTTPError) -> str:
    try:
        return exc.request.url.host
    except Exception:
        return "the remote service"
