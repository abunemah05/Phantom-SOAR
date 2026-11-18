"""Threat-intelligence enrichment across VirusTotal, AlienVault OTX, AbuseIPDB and ThreatFox.

Every provider result ("P") carries its own status so callers can tell evidence from absence:

    live            the provider answered with reputation data
    not_found       the provider answered but has no record of the indicator (no known reputation;
                    this is NOT evidence of maliciousness)
    not_configured  no API key is set for the provider (Configuration page or environment)
    error           the request failed (auth, timeout, unexpected response)
    rate_limited    the provider answered 429 or the local per-provider budget (requests per
                    minute / per day) is used up; carries retry_after_seconds. Never cached and
                    never evidence: it must not turn an indicator into "Clean"
    lab_fixture     simulation mode is on and the value is one of the explicit LAB_FIXTURES
    skipped         not looked up externally (private/reserved IP, unsupported indicator type)

Per-provider score (0-100); only "live" and "lab_fixture" results with a score count as evidence:

    VirusTotal  ratio based: weighted = vt_malicious_weight * malicious + vt_suspicious_weight *
                suspicious engines; ratio = weighted / engines that gave an answer;
                score = min(100, malicious_threshold * ratio / vt_malicious_threshold), so the
                Malicious score is reached when the ratio reaches vt_malicious_threshold
                (default 10 %, about 7 of 70 engines). Fewer than vt_min_detections weighted
                detections can never score Malicious. No engine results means no score
    AbuseIPDB   abuseConfidenceScore; 0 when AbuseIPDB marks the IP as whitelisted; an IP with no
                reports in the last 90 days is "not_found"
    OTX         0 when OTX validation marks the indicator as allow-listed; otherwise
                min(60, 20 + 10 * pulses). Pulses reference an indicator but do not confirm it, so
                OTX on its own can reach "Suspicious" but never "Malicious". 0 pulses is "not_found"
    ThreatFox   highest confidence_level among matching listings (missing level counts as the
                ThreatFox default of 50); a listing is never Clean (floor = suspicious threshold)

Consensus:

    threat_score  max score over evidence-backed providers, 0 when there is no evidence
    verdict       Unknown when no provider returned evidence; otherwise
                  Malicious (score >= 70), Suspicious (>= 30), Clean (< 30); thresholds are the
                  settings tip_malicious_threshold / tip_suspicious_threshold
    incomplete    true when a provider was rate limited or failed, so the answer should be
                  re-enriched later (retry_after_seconds says when)
    severity      Critical (Malicious and score >= 90), High (Malicious), Medium (Suspicious),
                  Low (Clean), None (Unknown)
"""
import base64
import ipaddress
import logging
import re
import math
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlparse, urlunparse

import httpx

from backend import integration_config

logger = logging.getLogger(__name__)

MALICIOUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 30
CRITICAL_THRESHOLD = 90

EVIDENCE_STATUSES = ("live", "lab_fixture")

PROVIDER_NAMES = {
    "virustotal": "VirusTotal",
    "alienvault_otx": "AlienVault OTX",
    "abuseipdb": "AbuseIPDB",
    "threatfox": "ThreatFox (abuse.ch)",
}
SOURCE_LABELS = {
    "virustotal": "VirusTotal v3",
    "alienvault_otx": "AlienVault OTX",
    "abuseipdb": "AbuseIPDB",
    "threatfox": "ThreatFox",
}
PROVIDER_SETTINGS = {
    "virustotal": "virustotal_api_key",
    "alienvault_otx": "otx_api_key",
    "abuseipdb": "abuseipdb_api_key",
    "threatfox": "threatfox_api_key",
}

_TYPE_ALIASES = {
    "IP": "IP", "IPV4": "IP", "IPV6": "IP", "IP_ADDRESS": "IP", "IPADDRESS": "IP",
    "HASH": "HASH", "MD5": "HASH", "SHA1": "HASH", "SHA256": "HASH", "FILE": "HASH",
    "FILE_HASH": "HASH", "FILEHASH": "HASH",
    "DOMAIN": "DOMAIN", "HOSTNAME": "DOMAIN", "FQDN": "DOMAIN",
    "URL": "URL", "URI": "URL",
}

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_SHARED_NET = ipaddress.ip_network("100.64.0.0/10")


def _lab(score: int, label: str, *tags: str) -> Dict[str, Any]:
    return {"threat_score": score, "label": label, "tags": list(tags)}


# Explicit lab values used ONLY when simulation mode is on. IPs come from the RFC 5737
# documentation ranges, hashes are the EICAR anti-malware test file, and domains/URLs use the
# reserved ".example" TLD (RFC 2606), so no real host or file is ever labelled malicious.
LAB_FIXTURES: Dict[str, Dict[str, Any]] = {
    "198.51.100.45": _lab(95, "Lab C2 server (Cobalt Strike beacon) used in the ransomware scenario", "c2", "ransomware"),
    "203.0.113.66": _lab(90, "Lab attacker IP that uploaded and operated a PHP web shell", "webshell", "exploitation"),
    "192.0.2.77": _lab(45, "Lab mail server that sent a credential-phishing email", "phishing", "spam"),
    "203.0.113.10": _lab(0, "Lab allow-listed partner VPN gateway", "allow-listed"),
    "44d88612fea8a8f36de82e1278abb02f": _lab(100, "EICAR anti-malware test file (MD5), detected by antivirus engines by design", "eicar", "test-file"),
    "3395856ce81f2b7382dee72602f798b642f14140": _lab(100, "EICAR anti-malware test file (SHA-1), detected by antivirus engines by design", "eicar", "test-file"),
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": _lab(100, "EICAR anti-malware test file (SHA-256), detected by antivirus engines by design", "eicar", "test-file"),
    "c2-beacon.lab.example": _lab(92, "Lab ransomware command-and-control beacon domain", "c2", "ransomware"),
    "login-verify.phish.example": _lab(60, "Lab credential-harvesting landing page domain", "phishing"),
    "http://login-verify.phish.example/verify": _lab(60, "Lab credential-harvesting landing page", "phishing"),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def verdict_for_score(
    score: Optional[int],
    malicious: int = MALICIOUS_THRESHOLD,
    suspicious: int = SUSPICIOUS_THRESHOLD,
) -> Optional[str]:
    if score is None:
        return None
    if score >= malicious:
        return "Malicious"
    if score >= suspicious:
        return "Suspicious"
    return "Clean"


def severity_for_verdict(verdict: str, score: int, critical: int = CRITICAL_THRESHOLD) -> Optional[str]:
    if verdict == "Malicious":
        return "Critical" if score >= critical else "High"
    return {"Suspicious": "Medium", "Clean": "Low"}.get(verdict)


def parse_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def non_public_ip_reason(ip: ipaddress._BaseAddress) -> Optional[str]:
    """Why an IP must not be looked up externally, or None for a public unicast address."""
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if any(ip.version == net.version and ip in net for net in _DOCUMENTATION_NETS):
        return "documentation range (RFC 5737 / RFC 3849), not routable"
    if ip.version == 4 and ip in _SHARED_NET:
        return "shared address space (RFC 6598, carrier-grade NAT)"
    if ip.is_private:
        return "private / internal address"
    if ip.is_reserved:
        return "reserved address"
    if not ip.is_global:
        return "non-global address"
    return None


def classify_indicator(value: str) -> Optional[str]:
    """Best-effort type detection: IP, HASH, URL or DOMAIN (None when unrecognised)."""
    v = (value or "").strip()
    if not v:
        return None
    if parse_ip(v):
        return "IP"
    if _HASH_RE.match(v.lower()):
        return "HASH"
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.IGNORECASE):
        return "URL"
    if _DOMAIN_RE.match(v.lower().rstrip(".")):
        return "DOMAIN"
    return None


def _normalize(ioc_type: str, value: str) -> Tuple[Optional[str], str]:
    declared = _TYPE_ALIASES.get((ioc_type or "").strip().upper().replace("-", "_"))
    v = (value or "").strip()
    detected = classify_indicator(v)
    norm = declared if declared and declared == detected else detected
    if norm == "IP":
        v = str(parse_ip(v))
    elif norm in ("HASH", "DOMAIN"):
        v = v.lower().rstrip(".")
    return norm, v


@dataclass(frozen=True)
class TipSettings:
    virustotal_api_key: str = ""
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    threatfox_api_key: str = ""
    simulation_mode: bool = False
    # Per-provider budgets. 0 disables the local limit (the provider's own 429 still applies).
    # Free tiers: VirusTotal public API 4/min and 500/day, AbuseIPDB standard plan 1000 checks/day.
    # https://docs.virustotal.com/reference/public-vs-premium-api
    # https://docs.abuseipdb.com/  (rate limiting section)
    vt_requests_per_minute: int = 4
    vt_requests_per_day: int = 500
    abuseipdb_daily_limit: int = 1000
    # Longest a request thread may wait for a local rate-limit slot before answering rate_limited.
    max_wait_seconds: float = 2.0
    # VirusTotal scoring (see module docstring).
    vt_malicious_weight: float = 1.0
    vt_suspicious_weight: float = 0.5
    vt_malicious_threshold: float = 0.10  # weighted detection ratio that reaches the Malicious score
    vt_min_detections: float = 5.0        # weighted detections needed before VT can score Malicious
    # Consensus verdict thresholds.
    malicious_threshold: int = MALICIOUS_THRESHOLD
    suspicious_threshold: int = SUSPICIOUS_THRESHOLD
    critical_threshold: int = CRITICAL_THRESHOLD

    def key_for(self, provider: str) -> str:
        return getattr(self, PROVIDER_SETTINGS[provider])


def _num(raw: Any, default: Any, cast=float, minimum: float = 0) -> Any:
    try:
        value = cast(float(str(raw).strip()))
    except (TypeError, ValueError, OverflowError):
        return default
    if math.isnan(value) or value < minimum:
        return default
    return value


def load_tip_settings(db=None) -> TipSettings:
    """Read TIP keys at call time so keys saved on the Configuration page take effect immediately."""
    from backend.database import SessionLocal

    own_session = db is None
    session = SessionLocal() if own_session else db
    d = TipSettings()
    try:
        def num(name: str, default: Any, cast=float, minimum: float = 0) -> Any:
            return _num(integration_config.get_setting(name, db=session, default=str(default)), default, cast, minimum)

        malicious = num("tip_malicious_threshold", d.malicious_threshold, int, 1)
        suspicious = num("tip_suspicious_threshold", d.suspicious_threshold, int, 1)
        critical = num("tip_critical_threshold", d.critical_threshold, int, 1)
        if not (suspicious < malicious <= critical <= 100):  # inconsistent values: fall back safely
            malicious, suspicious, critical = d.malicious_threshold, d.suspicious_threshold, d.critical_threshold
        return TipSettings(
            virustotal_api_key=integration_config.get_setting("virustotal_api_key", db=session),
            otx_api_key=integration_config.get_setting("otx_api_key", db=session),
            abuseipdb_api_key=integration_config.get_setting("abuseipdb_api_key", db=session),
            threatfox_api_key=integration_config.get_setting("threatfox_api_key", db=session),
            simulation_mode=integration_config.is_simulation_mode(db=session),
            vt_requests_per_minute=num("vt_requests_per_minute", d.vt_requests_per_minute, int),
            vt_requests_per_day=num("vt_requests_per_day", d.vt_requests_per_day, int),
            abuseipdb_daily_limit=num("abuseipdb_daily_limit", d.abuseipdb_daily_limit, int),
            max_wait_seconds=num("tip_max_wait_seconds", d.max_wait_seconds, float),
            vt_malicious_weight=num("vt_malicious_weight", d.vt_malicious_weight, float),
            vt_suspicious_weight=num("vt_suspicious_weight", d.vt_suspicious_weight, float),
            vt_malicious_threshold=num("vt_malicious_threshold", d.vt_malicious_threshold, float, 0.001),
            vt_min_detections=num("vt_min_detections", d.vt_min_detections, float),
            malicious_threshold=malicious,
            suspicious_threshold=suspicious,
            critical_threshold=critical,
        )
    finally:
        if own_session:
            session.close()


MAX_RETRY_AFTER = 24 * 3600
DEFAULT_RETRY_AFTER = 60


def parse_retry_after(value: Optional[str], default: int = DEFAULT_RETRY_AFTER) -> int:
    """Retry-After is either delta-seconds or an HTTP date (RFC 9110 10.2.3). Clamped to 1s..24h."""
    seconds: Optional[float] = None
    if value:
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
                seconds = None
    if seconds is None or math.isnan(seconds):
        seconds = default
    return int(min(MAX_RETRY_AFTER, max(1, math.ceil(seconds))))


class RateLimiter:
    """Thread-safe request budget: a sliding window (strict, so a burst can never exceed the
    vendor's "N per window") plus an optional daily quota that resets at 00:00 UTC (the reset
    time VirusTotal documents) and a block set from a provider 429 / Retry-After.

    acquire() never sleeps while holding the lock and never waits longer than ``max_wait``;
    when a slot is not available soon enough it returns (False, retry_after_seconds).
    """

    def __init__(self, per_window: int = 0, per_day: int = 0, window_seconds: float = 60.0):
        self.per_window = per_window
        self.per_day = per_day
        self.window_seconds = window_seconds
        self._stamps: List[float] = []
        self._day = None
        self._day_count = 0
        self._blocked_until = 0.0
        self._lock = threading.Lock()

    # Overridable in tests.
    _mono = staticmethod(time.monotonic)
    _utcnow = staticmethod(lambda: datetime.now(timezone.utc))

    def configure(self, per_window: int, per_day: int = 0) -> None:
        with self._lock:
            self.per_window, self.per_day = max(0, int(per_window)), max(0, int(per_day))

    def block(self, seconds: float) -> None:
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._mono() + max(0.0, seconds))

    def reset(self) -> None:
        with self._lock:
            self._stamps.clear()
            self._day, self._day_count, self._blocked_until = None, 0, 0.0

    def acquire(self, max_wait: float = 0.0) -> Tuple[bool, float]:
        """Reserve one request. Returns (True, seconds_to_sleep_first) or (False, retry_after)."""
        with self._lock:
            now = self._mono()
            if self._blocked_until > now:
                return False, self._blocked_until - now
            utc = self._utcnow()
            if self._day != utc.date():
                self._day, self._day_count = utc.date(), 0
            if self.per_day and self._day_count >= self.per_day:
                midnight = datetime.combine(utc.date() + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
                return False, max(1.0, (midnight - utc).total_seconds())
            wait = 0.0
            if self.per_window:
                self._stamps = [t for t in self._stamps if t > now - self.window_seconds]
                if len(self._stamps) >= self.per_window:
                    wait = self._stamps[-self.per_window] + self.window_seconds - now
                    if wait > max_wait:
                        return False, wait
                self._stamps.append(now + max(0.0, wait))
            self._day_count += 1
            return True, max(0.0, wait)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {"requests_today": self._day_count, "per_window": self.per_window, "per_day": self.per_day}


# Two-level public suffixes that are common enough to matter for OTX's "domain" vs "hostname"
# split. This is a documented heuristic, not the full Public Suffix List (no extra dependency):
# an unknown multi-label suffix is treated as a normal TLD, so its apex looks like a hostname and
# is queried as "hostname", which OTX still answers.
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nom", "ltd", "plc", "sch"}
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "ac.kr", "go.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw", "com.sg", "com.my", "co.id",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "co.th", "com.vn", "com.ph",
    "com.br", "net.br", "org.br", "gov.br", "com.ar", "com.mx", "com.co", "com.pe", "com.ve", "com.uy",
    "co.za", "org.za", "web.za", "co.ke", "co.il", "org.il", "com.tr", "com.eg", "com.sa", "com.ng",
    "com.ua", "com.pl", "com.ru", "com.es", "com.pt", "com.gr", "co.at", "or.at", "co.hu",
    "github.io", "gitlab.io", "herokuapp.com", "blogspot.com", "appspot.com", "azurewebsites.net",
    "cloudfront.net", "amazonaws.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
}


def registrable_domain(host: str) -> str:
    """Registrable ("apex") domain of a host using the heuristic suffix list above."""
    labels = [l for l in host.lower().strip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    # ccTLD with a generic second level (e.g. example.com.xx): two-letter TLD + known second level.
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return last2


def otx_domain_section(host: str) -> str:
    """OTX has /indicators/domain/<apex> and /indicators/hostname/<subdomain host>."""
    return "domain" if registrable_domain(host) == host.lower().strip(".") else "hostname"


def _provider_result(
    provider: str,
    status: str,
    threat_score: Optional[int] = None,
    summary: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    retry_after_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    has_evidence = status in EVIDENCE_STATUSES and threat_score is not None
    return {
        "provider": PROVIDER_NAMES[provider],
        "status": status,
        "threat_score": threat_score if has_evidence else None,
        "verdict": verdict_for_score(threat_score) if has_evidence else None,
        "summary": summary or {},
        "error": error,
        "retry_after_seconds": retry_after_seconds if status == "rate_limited" else None,
        "queried_at": _now_iso(),
    }


def _rate_limited(provider: str, retry_after: float, reason: str) -> Dict[str, Any]:
    return _provider_result(
        provider, "rate_limited", error=reason, retry_after_seconds=int(min(MAX_RETRY_AFTER, max(1, math.ceil(retry_after)))),
    )


def _http_error(resp: httpx.Response) -> str:
    code = resp.status_code
    if code in (401, 403):
        return f"authentication failed (HTTP {code}); check the API key"
    if code == 429:
        return "rate limited by the provider (HTTP 429)"
    return f"unexpected response (HTTP {code})"


def _exception_error(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "request timed out"
    if isinstance(exc, httpx.ConnectError):
        return "provider unreachable (connection failed)"
    if isinstance(exc, ValueError):
        return "provider returned an unreadable response"
    return f"request failed ({type(exc).__name__})"


class ThreatIntelligencePlatform:
    """Queries the configured providers in parallel and aggregates their evidence honestly."""

    VT_BASE = "https://www.virustotal.com/api/v3"
    OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(
        self,
        transport: Optional[httpx.BaseTransport] = None,
        timeout: float = 6.0,
        cache_ttl: float = 900.0,
        cache_max_entries: int = 2000,
    ):
        self.transport = transport  # tests inject httpx.MockTransport here
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache_max_entries = max(1, int(cache_max_entries))
        # LRU: most recently used last. Value = (stored_at, result).
        self._cache: "OrderedDict[Tuple[str, str, str], Tuple[float, Dict[str, Any]]]" = OrderedDict()
        self._lock = threading.Lock()
        self._limiters: Dict[str, RateLimiter] = {p: RateLimiter() for p in PROVIDER_NAMES}

    # -- plumbing ---------------------------------------------------------------------------

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=min(3.0, self.timeout)),
            transport=self.transport,
            follow_redirects=False,
        )

    def clear_cache(self) -> None:
        """Drop every cached answer (call after API keys change so re-enrichment is fresh)."""
        with self._lock:
            self._cache.clear()

    def reset_rate_limits(self) -> None:
        for limiter in self._limiters.values():
            limiter.reset()

    def rate_limit_status(self) -> Dict[str, Dict[str, Any]]:
        return {p: lim.snapshot() for p, lim in self._limiters.items()}

    def _cached(self, key: Tuple[str, str, str]) -> Optional[Dict[str, Any]]:
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.monotonic() - hit[0] < self.cache_ttl:
                self._cache.move_to_end(key)
                return {**hit[1], "cached": True}
            self._cache.pop(key, None)
        return None

    def _store(self, key: Tuple[str, str, str], result: Dict[str, Any]) -> None:
        # Only definitive answers are cached; errors and rate_limited are retried on the next lookup.
        if self.cache_ttl > 0 and result["status"] in ("live", "not_found"):
            with self._lock:
                self._cache[key] = (time.monotonic(), result)
                self._cache.move_to_end(key)
                while len(self._cache) > self.cache_max_entries:
                    self._cache.popitem(last=False)

    def _configure_limiter(self, provider: str, settings: TipSettings) -> RateLimiter:
        limiter = self._limiters[provider]
        if provider == "virustotal":
            limiter.configure(settings.vt_requests_per_minute, settings.vt_requests_per_day)
        elif provider == "abuseipdb":
            limiter.configure(0, settings.abuseipdb_daily_limit)
        else:  # no documented fixed budget; the provider's own 429 / Retry-After is honoured
            limiter.configure(0, 0)
        return limiter

    def _query(
        self, provider: str, ioc_type: str, value: str, api_key: str,
        settings: Optional[TipSettings] = None, force_refresh: bool = False,
    ) -> Dict[str, Any]:
        settings = settings or TipSettings()
        if not api_key:
            return _provider_result(
                provider, "not_configured",
                summary={"setting": PROVIDER_SETTINGS[provider]},
                error=f"{PROVIDER_NAMES[provider]} API key is not configured",
            )
        key = (provider, ioc_type, value)
        if not force_refresh:
            cached = self._cached(key)
            if cached:
                return cached
        limiter = self._configure_limiter(provider, settings)
        allowed, wait = limiter.acquire(max_wait=settings.max_wait_seconds)
        if not allowed:
            return _rate_limited(provider, wait, f"{PROVIDER_NAMES[provider]} request budget used up; retry later")
        if wait > 0:
            time.sleep(wait)  # bounded by settings.max_wait_seconds
        handler = {
            "virustotal": self.query_virustotal,
            "alienvault_otx": self.query_alienvault_otx,
            "abuseipdb": self.query_abuseipdb,
            "threatfox": self.query_threatfox,
        }[provider]
        try:
            result = handler(ioc_type, value, api_key, settings=settings)
        except Exception as exc:  # never let one provider break enrichment
            logger.warning(f"{PROVIDER_NAMES[provider]} lookup for {ioc_type} failed: {type(exc).__name__}")
            result = _provider_result(provider, "error", error=_exception_error(exc))
        if result["status"] == "rate_limited":
            limiter.block(result.get("retry_after_seconds") or DEFAULT_RETRY_AFTER)
        self._store(key, result)
        return result

    @staticmethod
    def _rate_limited_response(provider: str, resp: httpx.Response) -> Dict[str, Any]:
        retry = parse_retry_after(resp.headers.get("Retry-After"))
        return _rate_limited(provider, retry, "rate limited by the provider (HTTP 429)")

    # -- providers --------------------------------------------------------------------------

    def query_virustotal(self, ioc_type: str, value: str, api_key: str, settings: Optional[TipSettings] = None) -> Dict[str, Any]:
        settings = settings or TipSettings()
        if ioc_type == "HASH":
            path, gui = f"files/{value}", f"file/{value}"
        elif ioc_type == "IP":
            path, gui = f"ip_addresses/{value}", f"ip-address/{value}"
        elif ioc_type == "DOMAIN":
            path, gui = f"domains/{value}", f"domain/{value}"
        else:
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            path, gui = f"urls/{url_id}", f"url/{url_id}"
        permalink = f"https://www.virustotal.com/gui/{gui}"

        with self._client() as client:
            resp = client.get(f"{self.VT_BASE}/{path}", headers={"x-apikey": api_key, "Accept": "application/json"})
        if resp.status_code == 404:
            return _provider_result("virustotal", "not_found", summary={"permalink": permalink})
        if resp.status_code == 429:  # QuotaExceededError / TooManyRequestsError (docs.virustotal.com/reference/errors)
            return self._rate_limited_response("virustotal", resp)
        if resp.status_code != 200:
            return _provider_result("virustotal", "error", error=_http_error(resp))

        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        engines = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
        summary = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "engines_total": engines,
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "permalink": permalink,
        }
        if engines == 0:
            summary["note"] = "VirusTotal knows this object but has no engine results for it"
            return _provider_result("virustotal", "live", None, summary)

        score, weighted, ratio = self.virustotal_score(malicious, suspicious, harmless, undetected, settings)
        summary["weighted_detections"] = round(weighted, 2)
        summary["detection_ratio"] = round(ratio, 4)
        return _provider_result("virustotal", "live", score, summary)

    @staticmethod
    def virustotal_score(malicious: int, suspicious: int, harmless: int, undetected: int, settings: TipSettings) -> Tuple[int, float, float]:
        """Ratio based score: reaching vt_malicious_threshold maps to the Malicious threshold, and
        fewer than vt_min_detections weighted detections can never reach Malicious."""
        answered = malicious + suspicious + harmless + undetected
        weighted = settings.vt_malicious_weight * malicious + settings.vt_suspicious_weight * suspicious
        ratio = weighted / answered if answered else 0.0
        anchor = max(settings.vt_malicious_threshold, 0.001)
        score = int(min(100, round(settings.malicious_threshold * ratio / anchor)))
        if weighted < settings.vt_min_detections:
            score = min(score, settings.malicious_threshold - 1)
        return max(0, score), weighted, ratio

    def query_alienvault_otx(self, ioc_type: str, value: str, api_key: str, settings: Optional[TipSettings] = None) -> Dict[str, Any]:
        # https://otx.alienvault.com/api : /indicators/{IPv4|IPv6|domain|hostname|url|file}/<indicator>/general
        indicator = value
        if ioc_type == "IP":
            section = "IPv6" if ":" in value else "IPv4"
        elif ioc_type == "HASH":
            section = "file"
        elif ioc_type == "URL":
            section = "url"
            # The URL goes into the path as scheme://host/path; a fragment is never sent to servers,
            # and "?" must stay percent-encoded so it is not read as the start of OTX's own query string.
            parts = urlparse(value)
            indicator = urlunparse(parts._replace(fragment=""))
        else:
            # "domain" is the registrable (apex) domain, "hostname" anything below it.
            section = otx_domain_section(value)
        endpoint = f"{self.OTX_BASE}/{section}/{quote(indicator, safe=':/%')}/general"

        with self._client() as client:
            resp = client.get(endpoint, headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"})
        if resp.status_code == 404:
            return _provider_result("alienvault_otx", "not_found")
        if resp.status_code == 429:
            return self._rate_limited_response("alienvault_otx", resp)
        if resp.status_code != 200:
            return _provider_result("alienvault_otx", "error", error=_http_error(resp))

        data = resp.json() or {}
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        pulse_count = int(pulse_info.get("count", len(pulses)) or 0)
        families = set()
        for pulse in pulses:
            for fam in pulse.get("malware_families") or []:
                name = fam.get("display_name") if isinstance(fam, dict) else fam
                if name:
                    families.add(str(name))
        validation = [
            v.get("source") or v.get("name") for v in (data.get("validation") or []) if isinstance(v, dict)
        ]
        summary = {
            "pulse_count": pulse_count,
            "tags": sorted({str(t) for p in pulses for t in (p.get("tags") or [])})[:10],
            "malware_families": sorted(families)[:5],
            "adversaries": sorted({str(p["adversary"]) for p in pulses if p.get("adversary")})[:5],
            "allow_listed": bool(validation),
            "validation": [v for v in validation if v][:5],
        }
        if validation:
            return _provider_result("alienvault_otx", "live", 0, summary)
        if pulse_count == 0:
            return _provider_result("alienvault_otx", "not_found", summary=summary)
        return _provider_result("alienvault_otx", "live", min(60, 20 + 10 * pulse_count), summary)

    def query_abuseipdb(self, ioc_type: str, value: str, api_key: str, settings: Optional[TipSettings] = None) -> Dict[str, Any]:
        with self._client() as client:
            resp = client.get(
                self.ABUSEIPDB_URL,
                params={"ipAddress": value, "maxAgeInDays": "90"},
                headers={"Key": api_key, "Accept": "application/json"},
            )
        if resp.status_code == 429:  # daily limit; Retry-After per https://docs.abuseipdb.com/
            return self._rate_limited_response("abuseipdb", resp)
        if resp.status_code != 200:
            return _provider_result("abuseipdb", "error", error=_http_error(resp))

        data = (resp.json() or {}).get("data") or {}
        confidence = int(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)
        whitelisted = bool(data.get("isWhitelisted"))
        summary = {
            "abuse_confidence_score": confidence,
            "total_reports": reports,
            "num_distinct_users": data.get("numDistinctUsers"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "is_whitelisted": whitelisted,
            "is_tor": data.get("isTor"),
            "last_reported_at": data.get("lastReportedAt"),
        }
        if whitelisted:
            return _provider_result("abuseipdb", "live", 0, summary)
        if reports == 0:
            return _provider_result("abuseipdb", "not_found", summary=summary)
        return _provider_result("abuseipdb", "live", confidence, summary)

    @staticmethod
    def threatfox_request(ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
        """Request body per https://threatfox.abuse.ch/api/ (None when ThreatFox cannot search it).

        Hashes use search_hash (MD5 or SHA256 only). Everything else uses search_ioc; an IP is sent
        bare with a wildcard search because ThreatFox stores IP IOCs as "ip:port" (the matches are
        then filtered to the exact address), while domains and URLs use exact_match.
        """
        if ioc_type == "HASH":
            if len(value) not in (32, 64):
                return None
            return {"query": "search_hash", "hash": value}
        if ioc_type == "IP":
            return {"query": "search_ioc", "search_term": value, "exact_match": False}
        return {"query": "search_ioc", "search_term": value, "exact_match": True}

    @staticmethod
    def _threatfox_ip_matches(value: str, match: Dict[str, Any]) -> bool:
        ioc = str(match.get("ioc") or "").strip()
        if not ioc:
            return True  # nothing to compare with; trust the API
        host = ioc
        if ioc.startswith("["):
            host = ioc[1:].split("]", 1)[0]
        elif ioc.count(":") == 1:
            host = ioc.split(":", 1)[0]
        a, b = parse_ip(host), parse_ip(value)
        return a is not None and a == b

    def query_threatfox(self, ioc_type: str, value: str, api_key: str, settings: Optional[TipSettings] = None) -> Dict[str, Any]:
        settings = settings or TipSettings()
        body = self.threatfox_request(ioc_type, value)
        if body is None:
            return _provider_result(
                "threatfox", "skipped",
                summary={"reason": "ThreatFox searches MD5 and SHA256 hashes only"},
            )
        with self._client() as client:
            resp = client.post(self.THREATFOX_URL, json=body, headers={"Auth-Key": api_key, "Accept": "application/json"})
        if resp.status_code == 429:
            return self._rate_limited_response("threatfox", resp)
        if resp.status_code != 200:
            return _provider_result("threatfox", "error", error=_http_error(resp))

        payload = resp.json() or {}
        query_status = payload.get("query_status")
        if query_status == "no_result":
            return _provider_result("threatfox", "not_found")
        if query_status != "ok":
            return _provider_result("threatfox", "error", error=f"ThreatFox query_status '{query_status}'")

        matches = [m for m in (payload.get("data") or []) if isinstance(m, dict)]
        if ioc_type == "IP":
            matches = [m for m in matches if self._threatfox_ip_matches(value, m)]
        if not matches:
            return _provider_result("threatfox", "not_found")

        def level(m: Dict[str, Any]) -> int:
            try:
                return max(0, min(100, int(m.get("confidence_level"))))
            except (TypeError, ValueError):
                return 50  # ThreatFox default confidence when the reporter gave none

        confidence = max(level(m) for m in matches)
        # A listing means someone reported the IOC as malicious, so it is never "Clean", but the
        # score follows the reporters' confidence instead of jumping to the maximum.
        score = max(confidence, settings.suspicious_threshold)
        summary = {
            "matches": len(matches),
            "confidence_level": confidence,
            "malware_families": sorted({m["malware_printable"] for m in matches if m.get("malware_printable")})[:5],
            "threat_types": sorted({m["threat_type_desc"] for m in matches if m.get("threat_type_desc")})[:5],
            "tags": sorted({str(t) for m in matches for t in (m.get("tags") or [])})[:10],
            "first_seen": min((m["first_seen"] for m in matches if m.get("first_seen")), default=None),
            "last_seen": max((m["last_seen"] for m in matches if m.get("last_seen")), default=None),
        }
        return _provider_result("threatfox", "live", score, summary)

    # -- aggregation ------------------------------------------------------------------------

    @staticmethod
    def _lab_fixture(provider: str, fixture: Dict[str, Any]) -> Dict[str, Any]:
        return _provider_result(
            provider, "lab_fixture", fixture["threat_score"],
            summary={
                "fixture_label": fixture["label"],
                "tags": fixture["tags"],
                "note": "Simulation mode lab fixture, not a live threat-intelligence lookup",
            },
        )

    def _lookup_all(
        self, providers: List[str], ioc_type: str, value: str, settings: TipSettings, force_refresh: bool = False,
    ) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        pool = ThreadPoolExecutor(max_workers=len(providers), thread_name_prefix="tip")
        try:
            futures = {
                p: pool.submit(self._query, p, ioc_type, value, settings.key_for(p), settings, force_refresh)
                for p in providers
            }
            deadline = time.monotonic() + self.timeout * 2 + 1 + settings.max_wait_seconds
            for provider, future in futures.items():
                try:
                    results[provider] = future.result(timeout=max(0.1, deadline - time.monotonic()))
                except FutureTimeout:
                    results[provider] = _provider_result(provider, "error", error="request timed out")
                except Exception as exc:
                    results[provider] = _provider_result(provider, "error", error=_exception_error(exc))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return results

    def enrich_ioc(
        self, ioc_type: str, value: str, settings: Optional[TipSettings] = None, force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Enrich one indicator. Never raises; failures are reported per provider.

        force_refresh=True skips the cache read (the fresh answer still refreshes the cache)."""
        try:
            return self._enrich(ioc_type, value, settings, force_refresh)
        except Exception as exc:
            logger.exception(f"TIP enrichment failed unexpectedly for {ioc_type}")
            norm_type = (ioc_type or "").strip().upper()
            third = "abuseipdb" if norm_type == "IP" else "threatfox"
            providers = {
                p: _provider_result(p, "error", error=f"enrichment failed ({type(exc).__name__})")
                for p in ("virustotal", "alienvault_otx", third)
            }
            return self._aggregate(norm_type, (value or "").strip(), providers)

    def _enrich(self, ioc_type: str, value: str, settings: Optional[TipSettings], force_refresh: bool = False) -> Dict[str, Any]:
        settings = settings or load_tip_settings()
        norm_type, norm_value = _normalize(ioc_type, value)
        artifact_type = norm_type or (ioc_type or "").strip().upper()
        third = "abuseipdb" if norm_type == "IP" else "threatfox"
        provider_keys = ["virustotal", "alienvault_otx", third]

        fixture = LAB_FIXTURES.get(norm_value) if settings.simulation_mode else None
        if fixture:
            providers = {p: self._lab_fixture(p, fixture) for p in provider_keys}
        elif norm_type is None:
            providers = {
                p: _provider_result(p, "skipped", summary={"reason": "unrecognised indicator format"})
                for p in provider_keys
            }
        elif norm_type == "IP" and non_public_ip_reason(parse_ip(norm_value)):
            reason = non_public_ip_reason(parse_ip(norm_value))
            providers = {
                p: _provider_result(p, "skipped", summary={"reason": f"{reason}; never sent to external providers"})
                for p in provider_keys
            }
        else:
            providers = self._lookup_all(provider_keys, norm_type, norm_value, settings, force_refresh)
        return self._aggregate(artifact_type, norm_value, providers, settings)

    @staticmethod
    def _aggregate(
        artifact_type: str, value: str, providers: Dict[str, Dict[str, Any]], settings: Optional[TipSettings] = None,
    ) -> Dict[str, Any]:
        th = settings or TipSettings()
        for p in providers.values():  # providers may come from the cache: apply the current thresholds
            if p.get("threat_score") is not None:
                p["verdict"] = verdict_for_score(p["threat_score"], th.malicious_threshold, th.suspicious_threshold)
        evidence = {
            k: p for k, p in providers.items()
            if p["status"] in EVIDENCE_STATUSES and p["threat_score"] is not None
        }
        score = max((p["threat_score"] for p in evidence.values()), default=0)
        verdict = verdict_for_score(score, th.malicious_threshold, th.suspicious_threshold) if evidence else "Unknown"
        severity = severity_for_verdict(verdict, score, th.critical_threshold)

        statuses = [p["status"] for p in providers.values()]
        answered = [s for s in statuses if s in ("live", "not_found", "lab_fixture")]
        failed = "error" in statuses
        limited = "rate_limited" in statuses
        unconfigured = "not_configured" in statuses
        incomplete = failed or limited
        retry_after = max((p.get("retry_after_seconds") or 0 for p in providers.values() if p["status"] == "rate_limited"), default=0) or None
        if answered:
            enrichment_status = "partial" if (failed or limited or unconfigured) else "enriched"
        elif failed or limited:
            enrichment_status = "unavailable"
        elif unconfigured:
            enrichment_status = "not_configured"
        else:
            enrichment_status = "unavailable"  # every provider skipped (internal / unrecognised)

        simulated = "lab_fixture" in statuses
        names = ", ".join(PROVIDER_NAMES[k] for k in evidence)
        if evidence:
            reason = f"{verdict}: highest evidence-backed score {score}/100 from {names}."
            if simulated:
                reason += " Source is a simulation-mode lab fixture, not live threat intelligence."
            if incomplete:
                reason += " Incomplete: at least one provider was rate limited or failed; re-enrich later."
        elif all(s == "skipped" for s in statuses):
            skip_reason = next(iter(providers.values()))["summary"].get("reason", "not looked up")
            reason = f"Unknown: not looked up externally ({skip_reason})."
        elif limited:
            reason = (
                "Unknown: a threat-intel provider is rate limited, so this is not evidence that the indicator is clean"
                + (f"; retry in about {retry_after}s." if retry_after else ".")
            )
        elif "not_found" in statuses:
            reason = "Unknown: providers have no record of this indicator (no known reputation, not evidence of maliciousness)."
            if failed:
                reason += " Incomplete: at least one provider failed; re-enrich later."
        elif failed:
            reason = "Unknown: threat-intel providers could not be queried; see per-provider errors."
        else:
            reason = "Unknown: no threat-intel provider is configured."

        third_key = "abuseipdb" if "abuseipdb" in providers else "threatfox"
        return {
            "artifact_type": artifact_type,
            "value": value,
            "threat_score": score,
            "verdict": verdict,
            "severity": severity,
            "enrichment_status": enrichment_status,
            "simulated": simulated,
            "incomplete": incomplete,
            "retry_after_seconds": retry_after,
            "providers_queried": sum(1 for s in statuses if s in ("live", "not_found", "error")),
            "providers": providers,
            "consensus": {
                "score": score,
                "max_score": score,
                "verdict": verdict,
                "severity": severity,
                "evidence_providers": list(evidence),
                "incomplete": incomplete,
                "retry_after_seconds": retry_after,
                "method": "max score over providers with live or lab-fixture evidence",
                "thresholds": {
                    "malicious": th.malicious_threshold,
                    "suspicious": th.suspicious_threshold,
                    "critical_severity": th.critical_threshold,
                },
                "reason": reason,
                "sources": [SOURCE_LABELS[k] for k in providers],
            },
            # Legacy top-level keys kept for older clients.
            "virustotal": providers.get("virustotal"),
            "alienvault_otx": providers.get("alienvault_otx"),
            "abuseipdb": providers.get("abuseipdb") if third_key == "abuseipdb" else None,
            "threatfox": providers.get("threatfox") if third_key == "threatfox" else None,
        }


tip_client = ThreatIntelligencePlatform()


def clear_cache() -> None:
    """Clear the shared TIP cache (e.g. after API keys change on the Configuration page)."""
    tip_client.clear_cache()
