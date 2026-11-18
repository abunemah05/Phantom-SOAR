"""NIST NVD (API 2.0) lookups for CVEs that appear in an alert.

CVE identifiers are only ever taken from the alert's own text (rule, logs, payload fields);
nothing is inferred from keywords or severity. CVSS data comes from a live NVD lookup, which
needs ``nvd_api_key`` (Configuration page or NVD_API_KEY). Each CVE result has a status:

    live            NVD returned the CVE record
    not_found       NVD has no record of this CVE id
    not_configured  no NVD API key is set, so no lookup was made
    unavailable     the lookup failed (timeout, auth failure, bad response)
    rate_limited    NVD answered 429 or the local request budget is used up; retry_after_seconds
                    says when to try again (never cached)
    pending         allow_live=False and the CVE is not cached yet: no network call was made;
                    refresh_alert_vulnerabilities() fills the cache in the background

NVD allows 5 requests per rolling 30 seconds without an API key and 50 with one
(https://nvd.nist.gov/developers/start-here); the local budget defaults to 45 per 30 seconds and
is the setting nvd_requests_per_30s. Alert views should call analyze_alert_vulnerabilities with
allow_live=False and let a background task call refresh_alert_vulnerabilities(alert_id).

Only live CVSS data can make an alert eligible for the HOTL isolation recommendation
(CVSS >= 9.0 with a NETWORK attack vector); the response policy still decides what runs.
"""
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from backend import integration_config
from backend.integrations.tip import RateLimiter, _num, parse_retry_after

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HOTL_CVSS_THRESHOLD = 9.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pick_metric(metrics: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
    """Prefer the NVD primary CVSS v3.1 metric, then v4.0, v3.0, v2."""
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if entries:
            primary = next((m for m in entries if m.get("type") == "Primary"), entries[0])
            return version, primary
    return None, {}


class NationalVulnerabilityDatabase:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_CVES_PER_ALERT = 10

    def __init__(
        self,
        transport: Optional[httpx.BaseTransport] = None,
        timeout: float = 8.0,
        cache_ttl: float = 6 * 3600,
        cache_max_entries: int = 2000,
    ):
        self.transport = transport  # tests inject httpx.MockTransport here
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache_max_entries = max(1, int(cache_max_entries))
        self._cache: "OrderedDict[str, Tuple[float, Dict[str, Any]]]" = OrderedDict()  # LRU, newest last
        self._lock = threading.Lock()
        self._limiter = RateLimiter(per_window=45, window_seconds=30.0)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def _cache_get(self, cve_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            hit = self._cache.get(cve_id)
            if hit and time.monotonic() - hit[0] < self.cache_ttl:
                self._cache.move_to_end(cve_id)
                return {**hit[1], "cached": True}
            self._cache.pop(cve_id, None)
        return None

    def _cache_put(self, cve_id: str, record: Dict[str, Any]) -> None:
        with self._lock:
            self._cache[cve_id] = (time.monotonic(), record)
            self._cache.move_to_end(cve_id)
            while len(self._cache) > self.cache_max_entries:
                self._cache.popitem(last=False)

    def extract_cves_from_text(self, text: str) -> List[str]:
        """CVE identifiers in order of first appearance, upper-cased and de-duplicated."""
        if not text:
            return []
        seen: List[str] = []
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve not in seen:
                seen.append(cve)
        return seen

    def _base_record(
        self, cve_id: str, status: str, error: Optional[str] = None, retry_after_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return {
            "cve_id": cve_id,
            "status": status,
            "title": cve_id,
            "cvss_score": None,
            "cvss_version": None,
            "cvss_vector": None,
            "severity": None,
            "attack_vector": None,
            "cwe": None,
            "description": None,
            "published": None,
            "last_modified": None,
            "known_exploited": None,
            "patches": [nvd_url],
            "hitl_remediation": [
                f"Review {cve_id} at {nvd_url} and confirm whether the affected product and version are present on the alerting host.",
                "Apply the vendor fix or documented mitigation before closing the alert.",
            ],
            "hotl_action": "none",
            "hotl_action_description": "No live CVSS data, so no autonomous containment is recommended.",
            "nvd_url": nvd_url,
            "source": None,
            "error": error,
            "retry_after_seconds": retry_after_seconds if status == "rate_limited" else None,
            "queried_at": _now_iso(),
        }

    def query_nvd_api(self, cve_id: str, api_key: str) -> Dict[str, Any]:
        headers = {"apiKey": api_key, "Accept": "application/json"}
        try:
            with httpx.Client(timeout=httpx.Timeout(self.timeout, connect=3.0), transport=self.transport) as client:
                resp = client.get(self.BASE_URL, params={"cveId": cve_id}, headers=headers)
        except httpx.TimeoutException:
            return self._base_record(cve_id, "unavailable", "NVD request timed out")
        except httpx.HTTPError as exc:
            return self._base_record(cve_id, "unavailable", f"NVD unreachable ({type(exc).__name__})")

        if resp.status_code == 404:
            return self._base_record(cve_id, "not_found")
        if resp.status_code in (401, 403):
            return self._base_record(cve_id, "unavailable", f"NVD rejected the request (HTTP {resp.status_code}); check the API key or rate limit")
        if resp.status_code == 429:
            retry = parse_retry_after(resp.headers.get("Retry-After"), default=30)  # NVD window is 30 s
            self._limiter.block(retry)
            return self._base_record(cve_id, "rate_limited", "NVD rate limit reached (HTTP 429)", retry)
        if resp.status_code != 200:
            return self._base_record(cve_id, "unavailable", f"unexpected NVD response (HTTP {resp.status_code})")

        try:
            vulns = (resp.json() or {}).get("vulnerabilities") or []
        except ValueError:
            return self._base_record(cve_id, "unavailable", "NVD returned an unreadable response")
        if not vulns:
            return self._base_record(cve_id, "not_found")
        return self._parse_cve(cve_id, vulns[0].get("cve") or {})

    def _parse_cve(self, cve_id: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        record = self._base_record(cve_id, "live")
        version, metric = _pick_metric(cve.get("metrics") or {})
        data = metric.get("cvssData") or {}
        score = data.get("baseScore")
        attack_vector = data.get("attackVector") or data.get("accessVector")
        severity = data.get("baseSeverity") or metric.get("baseSeverity")

        description = next(
            (d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None
        )
        cwes = [
            d.get("value")
            for w in cve.get("weaknesses") or []
            for d in w.get("description") or []
            if d.get("value") and d.get("value").startswith("CWE-")
        ]
        references = [r.get("url") for r in cve.get("references") or [] if r.get("url")]
        known_exploited = bool(cve.get("cisaExploitAdd"))

        record.update({
            "title": cve.get("cisaVulnerabilityName") or cve_id,
            "cvss_score": float(score) if score is not None else None,
            "cvss_version": version,
            "cvss_vector": data.get("vectorString"),
            "severity": severity,
            "attack_vector": attack_vector,
            "cwe": ", ".join(dict.fromkeys(cwes)) or None,
            "description": description,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "known_exploited": known_exploited,
            "patches": [record["nvd_url"]] + references[:5],
            "source": "NIST NVD API 2.0",
        })
        if known_exploited and cve.get("cisaRequiredAction"):
            record["hitl_remediation"].append(f"CISA KEV required action: {cve['cisaRequiredAction']}")

        eligible = record["cvss_score"] is not None and record["cvss_score"] >= HOTL_CVSS_THRESHOLD and attack_vector == "NETWORK"
        record["hotl_action"] = "isolate_endpoint" if eligible else "none"
        record["hotl_action_description"] = (
            f"CVSS {record['cvss_score']} with a network attack vector: host isolation is recommended (subject to response policy)."
            if eligible else
            "CVSS below the autonomous-isolation threshold (9.0, network vector): analyst review required."
        )
        return record

    def get_vulnerability_details(
        self, cve_id: str, *, allow_live: bool = True, force_refresh: bool = False, db=None,
    ) -> Dict[str, Any]:
        """Look up a CVE in NVD. Never raises and never invents CVSS data.

        allow_live=False answers from the cache only (status "pending" on a miss, no network)."""
        cve_id = cve_id.strip().upper()
        if not CVE_RE.fullmatch(cve_id):
            return self._base_record(cve_id, "not_found", "not a valid CVE identifier")

        if not force_refresh:
            cached = self._cache_get(cve_id)
            if cached:
                return cached

        api_key = integration_config.get_setting("nvd_api_key", db=db)
        if not api_key:
            return self._base_record(cve_id, "not_configured", "NVD API key is not configured; no live lookup was made")
        if not allow_live:
            return self._base_record(cve_id, "pending", "not cached yet; a background refresh will fetch it")

        per_window = _num(integration_config.get_setting("nvd_requests_per_30s", db=db, default="45"), 45, int)
        max_wait = _num(integration_config.get_setting("tip_max_wait_seconds", db=db, default="2"), 2.0, float)
        self._limiter.configure(per_window)
        allowed, wait = self._limiter.acquire(max_wait=max_wait)
        if not allowed:
            return self._base_record(
                cve_id, "rate_limited", "NVD request budget used up; retry later", int(max(1, round(wait)))
            )
        if wait > 0:
            time.sleep(wait)

        record = self.query_nvd_api(cve_id, api_key)
        if record["status"] in ("live", "not_found"):
            self._cache_put(cve_id, record)
        return record

    def analyze_alert_vulnerabilities(
        self, alert: Any, db=None, *, allow_live: bool = True, force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """CVE context for an alert: CVEs named in its payload, their NVD data, and HOTL eligibility.

        ``alert`` is an alert dict or an object with ``to_dict()``. With allow_live=False only cached
        data is used and uncached CVEs report status "pending" (no network call)."""
        alert_dict = alert if isinstance(alert, dict) else alert.to_dict()
        raw = alert_dict.get("raw_payload") or {}
        try:
            payload_text = json.dumps(raw, default=str)
        except (TypeError, ValueError):
            payload_text = str(raw)
        found = self.extract_cves_from_text(f"{alert_dict.get('rule_id', '')} {payload_text}")
        truncated = max(0, len(found) - self.MAX_CVES_PER_ALERT)
        cves = found[: self.MAX_CVES_PER_ALERT]
        details = [
            self.get_vulnerability_details(c, allow_live=allow_live, force_refresh=force_refresh, db=db) for c in cves
        ]

        scores = [d["cvss_score"] for d in details if d["cvss_score"] is not None]
        max_cvss = max(scores) if scores else None
        statuses = {d["status"] for d in details}
        if not details:
            lookup_status = "no_cves"
        elif statuses <= {"live", "not_found"}:
            lookup_status = "live"
        elif statuses & {"live", "not_found"}:
            lookup_status = "partial"
        elif "pending" in statuses:
            lookup_status = "pending"
        elif statuses == {"not_configured"}:
            lookup_status = "not_configured"
        elif statuses == {"rate_limited"}:
            lookup_status = "rate_limited"
        else:
            lookup_status = "unavailable"

        eligible = [d for d in details if d["hotl_action"] == "isolate_endpoint"]
        if eligible:
            justification = (
                f"{eligible[0]['cve_id']} has live NVD CVSS {eligible[0]['cvss_score']} with a network attack vector; "
                "host isolation is recommended, subject to the response policy."
            )
        elif not details:
            justification = "No CVE identifiers appear in this alert."
        elif not scores:
            justification = "No live CVSS data is available for the CVEs in this alert; analyst review required."
        else:
            justification = "No CVE in this alert meets the autonomous-isolation threshold (CVSS >= 9.0, network vector); analyst review required."

        remediation: List[str] = []
        for d in details:
            for step in d["hitl_remediation"]:
                if step not in remediation:
                    remediation.append(step)

        return {
            "cves_detected": cves,
            "cves_truncated": truncated,
            "lookup_status": lookup_status,
            "incomplete": bool(statuses & {"pending", "rate_limited", "unavailable"}),
            "pending_cves": [d["cve_id"] for d in details if d["status"] == "pending"],
            "retry_after_seconds": max((d.get("retry_after_seconds") or 0 for d in details), default=0) or None,
            "max_cvss_score": max_cvss,
            "cvss_max_score": max_cvss,  # alias read by the current UI
            "vulnerabilities": details,
            "hitl_remediation_steps": remediation,
            "hitl_remediation_advice": " ".join(remediation) or None,
            "hotl_autonomous_policy": {
                "eligible_for_hotl": bool(eligible),
                "action_type": "isolate_endpoint" if eligible else "none",
                "justification": justification,
                "action_description": justification,
            },
        }

    def refresh_alert_vulnerabilities(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Background-task entry point: load the alert, look its CVEs up live and fill the cache.

        Opens its own DB session, never raises, returns the analysis (None if the alert is gone)."""
        from backend.database import SessionLocal
        from backend.models import Alert

        db = SessionLocal()
        try:
            alert = db.get(Alert, alert_id)
            if alert is None:
                return None
            return self.analyze_alert_vulnerabilities(alert.to_dict(), db, allow_live=True)
        except Exception as exc:
            logger.warning(f"NVD background refresh for alert {alert_id} failed: {type(exc).__name__}")
            return None
        finally:
            db.close()


nvd_client = NationalVulnerabilityDatabase()


def clear_cache() -> None:
    """Clear the shared NVD cache (e.g. after the NVD API key changes)."""
    nvd_client.clear_cache()
