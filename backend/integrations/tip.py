"""Threat-intelligence enrichment across VirusTotal, AlienVault OTX, AbuseIPDB and ThreatFox.

Every provider result ("P") carries its own status so callers can tell evidence from absence:

    live            the provider answered with reputation data
    not_found       the provider answered but has no record of the indicator (no known reputation;
                    this is NOT evidence of maliciousness)
    not_configured  no API key is set for the provider (Configuration page or environment)
    error           the request failed (auth, rate limit, timeout, unexpected response)
    lab_fixture     simulation mode is on and the value is one of the explicit LAB_FIXTURES
    skipped         not looked up externally (private/reserved IP, unsupported indicator type)

Per-provider score (0-100); only "live" and "lab_fixture" results with a score count as evidence:

    VirusTotal  min(100, 15 * malicious_engines + 5 * suspicious_engines); an object with no
                engine results has no score
    AbuseIPDB   abuseConfidenceScore; 0 when AbuseIPDB marks the IP as whitelisted; an IP with no
                reports in the last 90 days is "not_found"
    OTX         0 when OTX validation marks the indicator as allow-listed; otherwise
                min(60, 20 + 10 * pulses). Pulses reference an indicator but do not confirm it, so
                OTX on its own can reach "Suspicious" but never "Malicious". 0 pulses is "not_found"
    ThreatFox   highest confidence_level among matches (ThreatFox only lists malicious IOCs)

Consensus:

    threat_score  max score over evidence-backed providers, 0 when there is no evidence
    verdict       Unknown when no provider returned evidence; otherwise
                  Malicious (score >= 70), Suspicious (>= 30), Clean (< 30)
    severity      Critical (Malicious and score >= 90), High (Malicious), Medium (Suspicious),
                  Low (Clean), None (Unknown)
"""
import base64
import ipaddress
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

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


def verdict_for_score(score: Optional[int]) -> Optional[str]:
    if score is None:
        return None
    if score >= MALICIOUS_THRESHOLD:
        return "Malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Clean"


def severity_for_verdict(verdict: str, score: int) -> Optional[str]:
    if verdict == "Malicious":
        return "Critical" if score >= CRITICAL_THRESHOLD else "High"
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

    def key_for(self, provider: str) -> str:
        return getattr(self, PROVIDER_SETTINGS[provider])


def load_tip_settings(db=None) -> TipSettings:
    """Read TIP keys at call time so keys saved on the Configuration page take effect immediately."""
    from backend.database import SessionLocal

    own_session = db is None
    session = SessionLocal() if own_session else db
    try:
        return TipSettings(
            virustotal_api_key=integration_config.get_setting("virustotal_api_key", db=session),
            otx_api_key=integration_config.get_setting("otx_api_key", db=session),
            abuseipdb_api_key=integration_config.get_setting("abuseipdb_api_key", db=session),
            threatfox_api_key=integration_config.get_setting("threatfox_api_key", db=session),
            simulation_mode=integration_config.is_simulation_mode(db=session),
        )
    finally:
        if own_session:
            session.close()


def _provider_result(
    provider: str,
    status: str,
    threat_score: Optional[int] = None,
    summary: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    has_evidence = status in EVIDENCE_STATUSES and threat_score is not None
    return {
        "provider": PROVIDER_NAMES[provider],
        "status": status,
        "threat_score": threat_score if has_evidence else None,
        "verdict": verdict_for_score(threat_score) if has_evidence else None,
        "summary": summary or {},
        "error": error,
        "queried_at": _now_iso(),
    }


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
    ):
        self.transport = transport  # tests inject httpx.MockTransport here
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: Dict[Tuple[str, str, str], Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    # -- plumbing ---------------------------------------------------------------------------

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=min(3.0, self.timeout)),
            transport=self.transport,
            follow_redirects=False,
        )

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def _cached(self, key: Tuple[str, str, str]) -> Optional[Dict[str, Any]]:
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.monotonic() - hit[0] < self.cache_ttl:
                return {**hit[1], "cached": True}
            self._cache.pop(key, None)
        return None

    def _store(self, key: Tuple[str, str, str], result: Dict[str, Any]) -> None:
        # Only definitive answers are cached; errors are retried on the next lookup.
        if self.cache_ttl > 0 and result["status"] in ("live", "not_found"):
            with self._lock:
                self._cache[key] = (time.monotonic(), result)

    def _query(self, provider: str, ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
        if not api_key:
            return _provider_result(
                provider, "not_configured",
                summary={"setting": PROVIDER_SETTINGS[provider]},
                error=f"{PROVIDER_NAMES[provider]} API key is not configured",
            )
        key = (provider, ioc_type, value)
        cached = self._cached(key)
        if cached:
            return cached
        handler = {
            "virustotal": self.query_virustotal,
            "alienvault_otx": self.query_alienvault_otx,
            "abuseipdb": self.query_abuseipdb,
            "threatfox": self.query_threatfox,
        }[provider]
        try:
            result = handler(ioc_type, value, api_key)
        except Exception as exc:  # never let one provider break enrichment
            logger.warning(f"{PROVIDER_NAMES[provider]} lookup for {ioc_type} failed: {type(exc).__name__}")
            result = _provider_result(provider, "error", error=_exception_error(exc))
        self._store(key, result)
        return result

    # -- providers --------------------------------------------------------------------------

    def query_virustotal(self, ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
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
        if resp.status_code != 200:
            return _provider_result("virustotal", "error", error=_http_error(resp))

        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        engines = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
        summary = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "engines_total": engines,
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "permalink": permalink,
        }
        if engines == 0:
            summary["note"] = "VirusTotal knows this object but has no engine results for it"
            return _provider_result("virustotal", "live", None, summary)
        return _provider_result("virustotal", "live", min(100, 15 * malicious + 5 * suspicious), summary)

    def query_alienvault_otx(self, ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
        if ioc_type == "IP":
            section = "IPv6" if ":" in value else "IPv4"
        elif ioc_type == "HASH":
            section = "file"
        elif ioc_type == "URL":
            section = "url"
        else:
            section = "domain" if value.count(".") == 1 else "hostname"
        endpoint = f"{self.OTX_BASE}/{section}/{quote(value, safe=':/')}/general"

        with self._client() as client:
            resp = client.get(endpoint, headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"})
        if resp.status_code == 404:
            return _provider_result("alienvault_otx", "not_found")
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

    def query_abuseipdb(self, ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
        with self._client() as client:
            resp = client.get(
                self.ABUSEIPDB_URL,
                params={"ipAddress": value, "maxAgeInDays": "90"},
                headers={"Key": api_key, "Accept": "application/json"},
            )
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

    def query_threatfox(self, ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
        with self._client() as client:
            resp = client.post(
                self.THREATFOX_URL,
                json={"query": "search_ioc", "search_term": value},
                headers={"Auth-Key": api_key, "Accept": "application/json"},
            )
        if resp.status_code != 200:
            return _provider_result("threatfox", "error", error=_http_error(resp))

        body = resp.json() or {}
        query_status = body.get("query_status")
        if query_status == "no_result":
            return _provider_result("threatfox", "not_found")
        if query_status != "ok":
            return _provider_result("threatfox", "error", error=f"ThreatFox query_status '{query_status}'")

        matches = [m for m in (body.get("data") or []) if isinstance(m, dict)]
        if not matches:
            return _provider_result("threatfox", "not_found")
        confidence = max(int(m.get("confidence_level", 0) or 0) for m in matches)
        summary = {
            "matches": len(matches),
            "confidence_level": confidence,
            "malware_families": sorted({m["malware_printable"] for m in matches if m.get("malware_printable")})[:5],
            "threat_types": sorted({m["threat_type_desc"] for m in matches if m.get("threat_type_desc")})[:5],
            "tags": sorted({str(t) for m in matches for t in (m.get("tags") or [])})[:10],
            "first_seen": min((m["first_seen"] for m in matches if m.get("first_seen")), default=None),
            "last_seen": max((m["last_seen"] for m in matches if m.get("last_seen")), default=None),
        }
        return _provider_result("threatfox", "live", confidence, summary)

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

    def _lookup_all(self, providers: List[str], ioc_type: str, value: str, settings: TipSettings) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        pool = ThreadPoolExecutor(max_workers=len(providers), thread_name_prefix="tip")
        try:
            futures = {p: pool.submit(self._query, p, ioc_type, value, settings.key_for(p)) for p in providers}
            deadline = time.monotonic() + self.timeout * 2 + 1
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

    def enrich_ioc(self, ioc_type: str, value: str, settings: Optional[TipSettings] = None) -> Dict[str, Any]:
        """Enrich one indicator. Never raises; failures are reported per provider."""
        try:
            return self._enrich(ioc_type, value, settings)
        except Exception as exc:
            logger.exception(f"TIP enrichment failed unexpectedly for {ioc_type}")
            norm_type = (ioc_type or "").strip().upper()
            third = "abuseipdb" if norm_type == "IP" else "threatfox"
            providers = {
                p: _provider_result(p, "error", error=f"enrichment failed ({type(exc).__name__})")
                for p in ("virustotal", "alienvault_otx", third)
            }
            return self._aggregate(norm_type, (value or "").strip(), providers)

    def _enrich(self, ioc_type: str, value: str, settings: Optional[TipSettings]) -> Dict[str, Any]:
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
            providers = self._lookup_all(provider_keys, norm_type, norm_value, settings)
        return self._aggregate(artifact_type, norm_value, providers)

    @staticmethod
    def _aggregate(artifact_type: str, value: str, providers: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        evidence = {
            k: p for k, p in providers.items()
            if p["status"] in EVIDENCE_STATUSES and p["threat_score"] is not None
        }
        score = max((p["threat_score"] for p in evidence.values()), default=0)
        verdict = verdict_for_score(score) if evidence else "Unknown"
        severity = severity_for_verdict(verdict, score)

        statuses = [p["status"] for p in providers.values()]
        answered = [s for s in statuses if s in ("live", "not_found", "lab_fixture")]
        failed = "error" in statuses
        unconfigured = "not_configured" in statuses
        if answered:
            enrichment_status = "partial" if (failed or unconfigured) else "enriched"
        elif failed:
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
        elif all(s == "skipped" for s in statuses):
            skip_reason = next(iter(providers.values()))["summary"].get("reason", "not looked up")
            reason = f"Unknown: not looked up externally ({skip_reason})."
        elif "not_found" in statuses:
            reason = "Unknown: providers have no record of this indicator (no known reputation, not evidence of maliciousness)."
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
            "providers_queried": sum(1 for s in statuses if s in ("live", "not_found", "error")),
            "providers": providers,
            "consensus": {
                "score": score,
                "max_score": score,
                "verdict": verdict,
                "severity": severity,
                "evidence_providers": list(evidence),
                "method": "max score over providers with live or lab-fixture evidence",
                "thresholds": {
                    "malicious": MALICIOUS_THRESHOLD,
                    "suspicious": SUSPICIOUS_THRESHOLD,
                    "critical_severity": CRITICAL_THRESHOLD,
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
