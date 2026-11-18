"""Small helper for honouring HTTP 429 responses (used by the Okta, Jira and Slack connectors).

Header facts (verified against the vendors' docs):
  * Jira Cloud: 429 carries ``Retry-After`` (seconds) and ``X-RateLimit-Reset`` (ISO 8601);
    use Retry-After as the minimum delay.
    https://developer.atlassian.com/cloud/jira/platform/rate-limiting/
  * Okta: 429 carries ``X-Rate-Limit-Reset`` (UTC epoch seconds). ``Retry-After`` is not
    documented for Okta, so both headers are accepted.
    https://developer.okta.com/docs/reference/rl-best-practices
  * Slack incoming webhooks: 429 with ``Retry-After`` (seconds).
"""
import email.utils
import logging
import random
import time
from typing import Callable, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_BACKOFF_SECONDS = 2.0
MAX_WAIT_SECONDS = 15.0
MAX_ATTEMPTS = 3  # one request plus two retries after a 429

# Replaced in tests so no real sleeping happens.
_sleep: Callable[[float], None] = time.sleep


def retry_after_seconds(resp: httpx.Response, now: Optional[float] = None) -> Optional[float]:
    """Seconds the server asks us to wait, or None when it gave no usable hint."""
    now = time.time() if now is None else now
    raw = resp.headers.get("retry-after")
    if raw:
        raw = raw.strip()
        try:
            return max(0.0, float(raw))
        except ValueError:
            try:
                when = email.utils.parsedate_to_datetime(raw)
                return max(0.0, when.timestamp() - now)
            except (TypeError, ValueError):
                pass
    reset = resp.headers.get("x-rate-limit-reset")  # Okta: epoch seconds
    if reset:
        try:
            return max(0.0, float(reset) - now)
        except ValueError:
            pass
    return None


def send_honouring_429(
    send: Callable[[], httpx.Response],
    *,
    max_attempts: int = MAX_ATTEMPTS,
    max_wait: float = MAX_WAIT_SECONDS,
) -> httpx.Response:
    """Call ``send()``; on HTTP 429 wait (Retry-After, else exponential with jitter) and retry.

    A 429 means the request was rejected before it was processed, so retrying is safe even for
    non-idempotent calls. If the wait the server asks for exceeds ``max_wait`` the 429 response is
    returned immediately so the caller can report it honestly instead of blocking a worker.
    """
    resp = send()
    attempt = 1
    while resp.status_code == 429 and attempt < max_attempts:
        hint = retry_after_seconds(resp)
        wait = hint if hint is not None else DEFAULT_BACKOFF_SECONDS * (2 ** (attempt - 1))
        if hint is None:
            wait *= random.uniform(0.7, 1.3)
        if wait > max_wait:
            return resp
        logger.warning(f"HTTP 429 from {resp.request.url.host}; waiting {wait:.1f}s (attempt {attempt}/{max_attempts}).")
        _sleep(wait)
        resp = send()
        attempt += 1
    return resp
