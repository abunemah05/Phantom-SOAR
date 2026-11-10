"""NIST NVD (API 2.0) lookups for CVEs that appear in an alert.

CVE identifiers are only ever taken from the alert's own text (rule, logs, payload fields);
nothing is inferred from keywords or severity. CVSS data comes from a live NVD lookup, which
needs ``nvd_api_key`` (Configuration page or NVD_API_KEY). Each CVE result has a status:

    live            NVD returned the CVE record
    not_found       NVD has no record of this CVE id
    not_configured  no NVD API key is set, so no lookup was made
    unavailable     the lookup failed (timeout, rate limit, auth failure, bad response)

Only live CVSS data can make an alert eligible for the HOTL isolation recommendation
(CVSS >= 9.0 with a NETWORK attack vector); the response policy still decides what runs.
"""
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from backend import integration_config

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

    def __init__(self, transport: Optional[httpx.BaseTransport] = None, timeout: float = 8.0, cache_ttl: float = 6 * 3600):
        self.transport = transport  # tests inject httpx.MockTransport here
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

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

    def _base_record(self, cve_id: str, status: str, error: Optional[str] = None) -> Dict[str, Any]:
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
            return self._base_record(cve_id, "unavailable", "NVD rate limit reached (HTTP 429)")
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

    def get_vulnerability_details(self, cve_id: str) -> Dict[str, Any]:
        """Look up a CVE in NVD. Never raises and never invents CVSS data."""
        cve_id = cve_id.strip().upper()
        if not CVE_RE.fullmatch(cve_id):
            return self._base_record(cve_id, "not_found", "not a valid CVE identifier")

        with self._lock:
            hit = self._cache.get(cve_id)
            if hit and time.monotonic() - hit[0] < self.cache_ttl:
                return {**hit[1], "cached": True}

        api_key = integration_config.get_setting("nvd_api_key")
        if not api_key:
            return self._base_record(cve_id, "not_configured", "NVD API key is not configured; no live lookup was made")

        record = self.query_nvd_api(cve_id, api_key)
        if record["status"] in ("live", "not_found"):
            with self._lock:
                self._cache[cve_id] = (time.monotonic(), record)
        return record

    def analyze_alert_vulnerabilities(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """CVE context for an alert: CVEs named in its payload, their NVD data, and HOTL eligibility."""
        raw = alert_dict.get("raw_payload") or {}
        try:
            payload_text = json.dumps(raw, default=str)
        except (TypeError, ValueError):
            payload_text = str(raw)
        found = self.extract_cves_from_text(f"{alert_dict.get('rule_id', '')} {payload_text}")
        truncated = max(0, len(found) - self.MAX_CVES_PER_ALERT)
        cves = found[: self.MAX_CVES_PER_ALERT]
        details = [self.get_vulnerability_details(c) for c in cves]

        scores = [d["cvss_score"] for d in details if d["cvss_score"] is not None]
        max_cvss = max(scores) if scores else None
        statuses = {d["status"] for d in details}
        if not details:
            lookup_status = "no_cves"
        elif statuses <= {"live", "not_found"}:
            lookup_status = "live"
        elif statuses & {"live", "not_found"}:
            lookup_status = "partial"
        elif statuses == {"not_configured"}:
            lookup_status = "not_configured"
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


nvd_client = NationalVulnerabilityDatabase()
