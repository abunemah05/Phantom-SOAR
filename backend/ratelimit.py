"""HTTP rate limiting and login throttling (no external dependency).

Sliding-window counters kept in process memory; when PHANTOM_RATELIMIT_REDIS_URL points at a reachable
Redis the counters live there instead (shared by all workers). Any Redis error falls back to memory for
a short while, so a Redis outage never takes the API down (and never silently disables the limits).

Limits are tunable per scope with PHANTOM_RATE_LIMIT_<SCOPE>="<count>/<seconds>" ("off" disables).

Client addresses: X-Forwarded-For is honoured ONLY when the TCP peer is inside PHANTOM_TRUSTED_PROXIES
(comma separated IPs / CIDRs); otherwise any client could spoof its address and dodge the limits.
"""
import hashlib
import ipaddress
import logging
import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, List, Optional, Tuple

from fastapi import HTTPException, Request, status

from backend.integration_config import get_setting

logger = logging.getLogger(__name__)

# scope -> (count, window seconds) defaults
DEFAULT_LIMITS: Dict[str, Tuple[int, int]] = {
    "login": (30, 60),              # all sign-in attempts per client IP
    "change_password": (10, 60),
    "mfa": (10, 60),
    "webhooks": (600, 60),
    "test_connection": (10, 60),
    "service_key_failures": (20, 300),
    "ingest_failures": (20, 300),
}
# Failure thresholds for sign-in
PAIR_MAX_FAILURES = 5            # per (username, client IP): hard lock
PAIR_WINDOW = 15 * 60
IP_MAX_FAILURES = 30             # per client IP across all usernames: hard block
IP_WINDOW = 15 * 60
USER_DELAY_AFTER = 5             # per username across all IPs: delay only, never a lock
USER_WINDOW = 15 * 60
MAX_TRACKED_WINDOW = 3600


# --- storage backends --------------------------------------------------------------------
class _MemoryStore:
    def __init__(self) -> None:
        self._data: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()
        self._ops = 0

    def hit(self, key: str, window: float, now: float) -> int:
        with self._lock:
            q = self._data.setdefault(key, deque())
            self._trim(q, window, now)
            q.append(now)
            self._ops += 1
            if self._ops % 2000 == 0:
                self._sweep(now)
            return len(q)

    def count(self, key: str, window: float, now: float) -> int:
        with self._lock:
            q = self._data.get(key)
            if not q:
                return 0
            self._trim(q, window, now)
            return len(q)

    def oldest(self, key: str) -> Optional[float]:
        with self._lock:
            q = self._data.get(key)
            return q[0] if q else None

    def reset(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def reset_prefix(self, prefix: str) -> None:
        with self._lock:
            for k in [k for k in self._data if k.startswith(prefix)]:
                self._data.pop(k, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    @staticmethod
    def _trim(q: Deque[float], window: float, now: float) -> None:
        while q and q[0] <= now - window:
            q.popleft()

    def _sweep(self, now: float) -> None:
        for k in [k for k, q in self._data.items() if not q or q[-1] <= now - MAX_TRACKED_WINDOW]:
            self._data.pop(k, None)


class _RedisStore:
    """Sorted-set sliding window. Every method may raise; the facade falls back to memory."""

    def __init__(self, client) -> None:
        self.r = client
        self._seq = 0

    def hit(self, key: str, window: float, now: float) -> int:
        self._seq += 1
        pipe = self.r.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {f"{now}:{self._seq}:{time.monotonic_ns()}": now})
        pipe.zcard(key)
        pipe.expire(key, int(window) + 5)
        return int(pipe.execute()[2])

    def count(self, key: str, window: float, now: float) -> int:
        pipe = self.r.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zcard(key)
        return int(pipe.execute()[1])

    def oldest(self, key: str) -> Optional[float]:
        items = self.r.zrange(key, 0, 0, withscores=True)
        return float(items[0][1]) if items else None

    def reset(self, key: str) -> None:
        self.r.delete(key)

    def reset_prefix(self, prefix: str) -> None:
        for k in self.r.scan_iter(match=prefix + "*", count=500):
            self.r.delete(k)

    def clear(self) -> None:
        self.reset_prefix("phantom:rl:")


class _Limiter:
    def __init__(self) -> None:
        self.memory = _MemoryStore()
        self._redis: Optional[_RedisStore] = None
        self._redis_url_loaded: Optional[str] = None
        self._redis_down_until = 0.0
        self._lock = threading.Lock()

    def _redis_store(self) -> Optional[_RedisStore]:
        url = get_setting("phantom_ratelimit_redis_url")
        if not url:
            return None
        if time.time() < self._redis_down_until:
            return None
        with self._lock:
            if self._redis is not None and self._redis_url_loaded == url:
                return self._redis
            try:
                import redis  # optional dependency

                client = redis.Redis.from_url(url, socket_connect_timeout=0.3, socket_timeout=0.3)
                client.ping()
                self._redis, self._redis_url_loaded = _RedisStore(client), url
                return self._redis
            except Exception as exc:
                logger.warning(f"Rate-limit Redis unavailable ({exc.__class__.__name__}); using in-process counters.")
                self._redis_down_until = time.time() + 30
                self._redis = None
                return None

    def _call(self, name: str, *args):
        store = self._redis_store()
        if store is not None:
            try:
                return getattr(store, name)(*args)
            except Exception as exc:
                logger.warning(f"Rate-limit Redis error ({exc.__class__.__name__}); falling back to memory.")
                self._redis_down_until = time.time() + 30
                self._redis = None
        return getattr(self.memory, name)(*args)

    def hit(self, key: str, window: float) -> int:
        return self._call("hit", f"phantom:rl:{key}", window, time.time())

    def count(self, key: str, window: float) -> int:
        return self._call("count", f"phantom:rl:{key}", window, time.time())

    def oldest(self, key: str) -> Optional[float]:
        return self._call("oldest", f"phantom:rl:{key}")

    def reset(self, key: str) -> None:
        self._call("reset", f"phantom:rl:{key}")

    def reset_prefix(self, prefix: str) -> None:
        self._call("reset_prefix", f"phantom:rl:{prefix}")

    def clear(self) -> None:
        self.memory.clear()
        if self._redis_store() is not None:
            try:
                self._redis.clear()  # type: ignore[union-attr]
            except Exception:
                pass


limiter = _Limiter()


def reset_all() -> None:
    """Drop every counter (tests)."""
    limiter.clear()


# --- client address ------------------------------------------------------------------------
def _trusted_networks() -> List:
    nets = []
    for item in (get_setting("phantom_trusted_proxies") or "").replace("\n", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning(f"Ignoring invalid PHANTOM_TRUSTED_PROXIES entry {item!r}.")
    return nets


def _in(nets, value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(ip in n for n in nets)


def get_client_ip(request: Request) -> str:
    """Peer address, or the right-most untrusted X-Forwarded-For hop when the peer is a trusted proxy."""
    peer = request.client.host if request.client else "unknown"
    nets = _trusted_networks()
    if not nets or not _in(nets, peer):
        return peer
    forwarded = request.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _in(nets, hop):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return peer
    return peer


# --- generic limits ----------------------------------------------------------------------
def get_limit(scope: str) -> Optional[Tuple[int, int]]:
    default = DEFAULT_LIMITS[scope]
    raw = get_setting(f"phantom_rate_limit_{scope}").strip().lower()
    if not raw:
        return default
    if raw in ("off", "0", "none", "disabled"):
        return None
    try:
        count, _, window = raw.partition("/")
        return max(1, int(count)), max(1, int(window)) if window else default[1]
    except ValueError:
        logger.warning(f"Invalid PHANTOM_RATE_LIMIT_{scope.upper()}={raw!r}; using the default.")
        return default


def _too_many(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests. Slow down and try again shortly.",
        headers={"Retry-After": str(max(1, retry_after))},
    )


def enforce(scope: str, key: str) -> None:
    """Count one request for `key` under `scope`; raise 429 when over the limit."""
    limit = get_limit(scope)
    if limit is None:
        return
    count, window = limit
    if limiter.hit(f"{scope}:{key}", window) > count:
        raise _too_many(window // 2 or 1)


def ip_rate_limit(scope: str) -> Callable[..., None]:
    """FastAPI dependency: per-client-IP limit for `scope`."""
    def _dependency(request: Request) -> None:
        enforce(scope, get_client_ip(request))
    return _dependency


# --- sign-in throttling ----------------------------------------------------------------------
def _uh(username: str) -> str:
    return hashlib.sha256((username or "").strip().lower()[:200].encode("utf-8")).hexdigest()[:20]


def _pair(scope: str, username: str, ip: str) -> str:
    return f"pair:{scope}:{_uh(username)}:{ip}"


def ip_blocked(ip: str) -> bool:
    """Too many failed credential checks from this address (any username)."""
    return limiter.count(f"fail:ip:{ip}", IP_WINDOW) >= IP_MAX_FAILURES


def pair_locked(scope: str, username: str, ip: str) -> bool:
    """Locked only for this (username, client IP) pair, so a stranger cannot lock the real user out."""
    return limiter.count(_pair(scope, username, ip), PAIR_WINDOW) >= PAIR_MAX_FAILURES


def register_failure(scope: str, username: str, ip: str) -> Dict[str, int]:
    return {
        "pair": limiter.hit(_pair(scope, username, ip), PAIR_WINDOW),
        "username": limiter.hit(f"fail:user:{_uh(username)}", USER_WINDOW),
        "ip": limiter.hit(f"fail:ip:{ip}", IP_WINDOW),
    }


def clear_pair(scope: str, username: str, ip: str) -> None:
    limiter.reset(_pair(scope, username, ip))


def clear_username(username: str) -> None:
    """Admin unlock: forget every failure recorded for this username (all scopes, all addresses)."""
    limiter.reset(f"fail:user:{_uh(username)}")
    for scope in ("login", "chpw", "mfa"):
        limiter.reset_prefix(f"pair:{scope}:{_uh(username)}:")


def username_delay(username: str) -> float:
    """Progressive delay (seconds) once a username has seen many failures from anywhere. Never a lock."""
    try:
        base = float(get_setting("phantom_login_delay_seconds", default="0.25"))
    except ValueError:
        base = 0.25
    failures = limiter.count(f"fail:user:{_uh(username)}", USER_WINDOW)
    if failures < USER_DELAY_AFTER or base <= 0:
        return 0.0
    return min(base * (failures - USER_DELAY_AFTER + 1), 3.0)
