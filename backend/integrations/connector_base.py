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
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Optional, Union

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


def http_client(verify: Union[bool, str] = True) -> httpx.Client:
    """Factory for outbound HTTP clients (tests replace it with a MockTransport client).

    ``verify`` is True, False, or the path of a CA bundle file (httpx accepts a path string).
    """
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


# --- Retries -----------------------------------------------------------------------

# Module-level so tests can patch them: ``monkeypatch.setattr(connector_base, "sleep", ...)``.
sleep = time.sleep
jitter = random.random  # returns a float in [0, 1)

RETRY_BASE_DELAY = 0.5
RETRY_MAX_DELAY = 8.0
RETRY_AFTER_CAP = 30.0  # never honour a Retry-After longer than this (seconds)
RETRY_STATUSES = frozenset({429, 502, 503, 504})
RETRY_AFTER_STATUSES = frozenset({429, 503})  # the only ones a non-idempotent request may retry

# Failures that happen before the server can have processed the request.
_PRE_REQUEST_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)


def parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP-date), capped; None if absent/invalid."""
    if not value:
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            seconds = (when - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            return None
    return min(max(seconds, 0.0), RETRY_AFTER_CAP)


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter: base * 2^(attempt-1), plus up to 100% jitter, capped."""
    base = RETRY_BASE_DELAY * (2 ** (attempt - 1))
    return min(base + jitter() * base, RETRY_MAX_DELAY)


def attempts_of(obj: Any) -> int:
    """How many attempts request_with_retry made for a response or for the exception it raised."""
    if isinstance(obj, httpx.Response):
        return int(obj.extensions.get("phantom_attempts", 1))
    return int(getattr(obj, "phantom_attempts", 1))


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    idempotent: bool = True,
    max_attempts: int = 3,
    **kwargs: Any,
) -> httpx.Response:
    """client.request() with bounded retries and exponential backoff plus jitter.

    Retried: connect errors, timeouts and HTTP 502/503/504/429 (Retry-After is honoured, capped at
    RETRY_AFTER_CAP seconds). For ``idempotent=False`` requests (which could act twice if the
    first attempt was in fact processed) only failures that happen before the server can have
    processed the request are retried: connect errors and 429/503 that carry Retry-After. A read
    timeout is never retried for them.

    Returns the last response (callers still call raise_for_status()); if every attempt raised, the
    last exception is re-raised. The number of attempts is available from ``attempts_of()``:
    ``response.extensions["phantom_attempts"]`` or ``exc.phantom_attempts``.
    """
    max_attempts = max(1, int(max_attempts))
    attempt = 0
    while True:
        attempt += 1
        try:
            response = client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            exc.phantom_attempts = attempt  # type: ignore[attr-defined]
            if attempt >= max_attempts or not _error_is_retryable(exc, idempotent):
                raise
            delay = _backoff_delay(attempt)
            logger.info(f"[retry] {method} {_safe_host(url)} failed ({exc.__class__.__name__}); "
                        f"attempt {attempt}/{max_attempts}, retrying in {delay:.2f}s")
            sleep(delay)
            continue

        response.extensions["phantom_attempts"] = attempt
        retry_after = parse_retry_after(response.headers.get("Retry-After"))
        if attempt >= max_attempts or not _status_is_retryable(response.status_code, retry_after, idempotent):
            return response
        delay = retry_after if retry_after is not None else _backoff_delay(attempt)
        logger.info(f"[retry] {method} {_safe_host(url)} got HTTP {response.status_code}; "
                    f"attempt {attempt}/{max_attempts}, retrying in {delay:.2f}s")
        response.close()
        sleep(delay)


def _error_is_retryable(exc: Exception, idempotent: bool) -> bool:
    if isinstance(exc, _PRE_REQUEST_ERRORS):
        return True
    if not idempotent:
        return False
    # Idempotent requests may also retry after a read timeout or a dropped connection.
    return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError))


def _status_is_retryable(status: int, retry_after: Optional[float], idempotent: bool) -> bool:
    if status not in RETRY_STATUSES:
        return False
    if idempotent:
        return True
    return status in RETRY_AFTER_STATUSES and retry_after is not None


def _safe_host(url: str) -> str:
    try:
        return httpx.URL(url).host
    except Exception:
        return "remote"
