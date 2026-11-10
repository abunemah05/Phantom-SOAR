"""Alert ingestion pipeline shared by the SIEM / EDR / XDR webhooks and the lab demo.

ingest_alert() turns a raw payload into an Alert:
  1. severity from the telemetry itself (Wazuh rule.level, or the EDR/XDR "severity" field)
  2. IOC extraction (IPv4/IPv6, MD5/SHA-1/SHA-256, domains, URLs), de-duplicated and capped
  3. threat-intel enrichment of every IOC, stored with its verdict and per-provider evidence
  4. at most one step of severity escalation, never above High, and only when an IOC has a
     Malicious verdict backed by live or lab-fixture evidence (Unknown never escalates)
  5. a telemetry log entry, then dispatch of the response runner (Celery when the broker is
     reachable, otherwise synchronously)
"""
import ipaddress
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from backend.config import settings
from backend.crud import create_alert, create_ioc_artifact, get_ioc_artifacts_by_alert
from backend.integrations import tip
from backend.models import Alert

logger = logging.getLogger(__name__)

SEVERITIES = ("Low", "Medium", "High", "Critical")
SOURCES = ("wazuh", "edr", "xdr", "demo")
SOURCE_LABELS = {
    "wazuh": "Wazuh SIEM",
    "edr": "EDR (Endpoint Agent)",
    "xdr": "XDR (Cross-Layer Correlation)",
    "demo": "Wazuh SIEM (lab simulation)",
}
LOG_SOURCES = {"wazuh": "SIEM", "edr": "EDR", "xdr": "XDR", "demo": "SIEM"}

MAX_IOCS_PER_ALERT = 25
MAX_IOC_LENGTH = 500  # IocArtifact.value column size
ENRICH_WORKERS = 4
DEFAULT_SEVERITY = "Medium"

# Keys that describe the detection or the reporting asset rather than indicators.
_SKIP_KEYS = {
    "rule", "agent", "manager", "decoder", "predecoder", "cluster", "input", "location",
    "id", "timestamp", "@timestamp", "severity", "rule_id", "alert_id", "incident_id",
    "detection_id", "hostname", "hosts", "host", "target", "mitre", "mitre_tactic",
    "mitre_technique", "correlated_layers", "full_log",
}
# Fields whose whole value is expected to be a domain name.
_DOMAIN_KEYS = {"domain", "query", "qname", "dns_query", "dest_domain", "fqdn", "srchost", "dsthost"}
# TLDs accepted for domains found in free text; file extensions such as .exe/.php/.zip/.sh are
# deliberately absent so file names are not mistaken for domains.
_FREE_TEXT_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "xyz", "top", "online", "site", "club",
    "live", "shop", "store", "app", "dev", "cloud", "tech", "space", "website", "icu", "buzz",
    "cn", "ru", "su", "ir", "kp", "br", "in", "de", "uk", "fr", "nl", "it", "es", "jp", "kr",
    "tw", "hk", "vn", "id", "ua", "by", "kz", "tr", "ar", "mx", "cc", "tk", "ml", "ga", "cf",
    "gq", "pw", "ws", "to", "ly", "eu", "us", "ca", "au", "edu", "gov", "mil", "int",
    "example", "test",
}
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "php", "sh", "py", "ps1", "bat", "cmd", "js", "vbs", "jar", "zip", "rar",
    "7z", "gz", "tar", "txt", "log", "tmp", "dat", "bin", "so", "doc", "docx", "xls", "xlsx",
    "pdf", "lnk", "msi", "scr", "jpg", "png", "gif", "html", "htm", "aspx", "asp", "jsp", "xml",
    "json", "conf", "cfg", "ini", "md", "mov",
}
_INTERNAL_SUFFIXES = (
    ".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".localdomain", ".arpa",
    ".localhost", ".invalid",
)

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`\\]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?![\w:])")
_DOMAIN_RE = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)


# ----------------------------------------------------------------------------------------
# Severity
# ----------------------------------------------------------------------------------------

def map_wazuh_level_to_severity(level: int) -> str:
    """Map a Wazuh rule level (0-16) to Phantom SOAR severity."""
    if level >= 12:
        return "Critical"
    if level >= 8:
        return "High"
    if level >= 5:
        return "Medium"
    return "Low"


def normalize_severity(value: Any) -> Optional[str]:
    text = str(value or "").strip().capitalize()
    return text if text in SEVERITIES else None


def determine_severity(payload: Dict[str, Any], source: str) -> Tuple[str, str]:
    """Severity taken from telemetry, plus a human-readable basis for it.

    Wazuh-format payloads (wazuh, demo) use rule.level only; any top-level "severity" key is
    ignored so a sender cannot pick its own severity. EDR/XDR use their "severity" field.
    """
    if source in ("wazuh", "demo"):
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        try:
            level = int(rule.get("level"))
        except (TypeError, ValueError):
            return DEFAULT_SEVERITY, f"rule.level missing or invalid; defaulted to {DEFAULT_SEVERITY}"
        return map_wazuh_level_to_severity(level), f"Wazuh rule.level {level}"

    raw = payload.get("severity")
    severity = normalize_severity(raw)
    if severity:
        return severity, f"{source.upper()} severity field '{raw}'"
    if raw in (None, ""):
        return DEFAULT_SEVERITY, f"severity field missing; defaulted to {DEFAULT_SEVERITY}"
    return DEFAULT_SEVERITY, f"severity field '{raw}' is not Critical/High/Medium/Low; defaulted to {DEFAULT_SEVERITY}"


def escalated_severity(current: str, verdicts: Iterable[str]) -> Optional[str]:
    """One step up (capped at High) when any IOC is Malicious; None when no change applies."""
    if "Malicious" not in set(verdicts):
        return None
    rank = SEVERITIES.index(current) if current in SEVERITIES else SEVERITIES.index(DEFAULT_SEVERITY)
    if rank >= SEVERITIES.index("High"):
        return None
    return SEVERITIES[rank + 1]


# ----------------------------------------------------------------------------------------
# IOC extraction
# ----------------------------------------------------------------------------------------

def _iter_strings(node: Any, key: str = "", depth: int = 0) -> Iterable[Tuple[str, str]]:
    """(key, string) pairs from nested dicts/lists, bounded in depth."""
    if depth > 8:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() in _SKIP_KEYS and depth == 0:
                continue
            yield from _iter_strings(v, str(k).lower(), depth + 1)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_strings(item, key, depth + 1)
    elif isinstance(node, str):
        yield key, node[:65536]


def _valid_domain(candidate: str, from_domain_field: bool) -> Optional[str]:
    domain = candidate.lower().rstrip(".")
    if domain == "localhost" or domain.endswith(_INTERNAL_SUFFIXES):
        return None
    if tip.classify_indicator(domain) != "DOMAIN":
        return None
    tld = domain.rsplit(".", 1)[-1]
    if tld in _FILE_EXTENSIONS:
        return None
    if not from_domain_field and tld not in _FREE_TEXT_TLDS:
        return None
    return domain


def _usable_ip(candidate: str, excluded: set) -> Optional[str]:
    ip = tip.parse_ip(candidate)
    if ip is None:
        return None
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return None
    value = str(ip)
    return None if value in excluded else value


def _scan_text(text: str, key: str, excluded_ips: set, excluded_hosts: set) -> List[Tuple[str, str]]:
    """Indicators in one string, in order: URLs (plus their host), hashes, IPs, domains."""
    found: List[Tuple[str, str]] = []
    remainder = text

    for match in _URL_RE.findall(text):
        url = match.rstrip(").,;:!?]}'\"")
        found.append(("URL", url))
        host = (urlparse(url).hostname or "").lower()
        if host and host not in excluded_hosts:
            ip = _usable_ip(host, excluded_ips)
            if ip:
                found.append(("IP", ip))
            elif tip.parse_ip(host) is None:
                domain = _valid_domain(host, from_domain_field=True)
                if domain:
                    found.append(("Domain", domain))
        remainder = remainder.replace(match, " ")

    remainder = _EMAIL_RE.sub(" ", remainder)

    for h in _HASH_RE.findall(remainder):
        if not h.isdigit() and len(set(h.lower())) > 2:
            found.append(("Hash", h.lower()))
    remainder = _HASH_RE.sub(" ", remainder)

    for candidate in _IPV4_RE.findall(remainder):
        ip = _usable_ip(candidate, excluded_ips)
        if ip:
            found.append(("IP", ip))
    for raw in _IPV6_RE.findall(remainder):
        for candidate in (raw, raw.rstrip(".:"), raw.strip(".:")):
            ip = tip.parse_ip(candidate)
            if ip is not None and ip.version == 6:
                usable = _usable_ip(candidate, excluded_ips)
                if usable:
                    found.append(("IP", usable))
                break
    remainder = _IPV4_RE.sub(" ", remainder)

    from_domain_field = key in _DOMAIN_KEYS
    for candidate in _DOMAIN_RE.findall(remainder):
        domain = _valid_domain(candidate, from_domain_field)
        if domain and domain not in excluded_hosts:
            found.append(("Domain", domain))
    return found


def extract_iocs(payload: Dict[str, Any], limit: int = MAX_IOCS_PER_ALERT) -> Tuple[List[Dict[str, str]], int]:
    """Indicators from payload fields and full_log, de-duplicated, capped at ``limit``.

    Returns (iocs, dropped) where dropped counts unique indicators beyond the cap. The
    reporting agent's own IP and hostname are not indicators and are excluded.
    """
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    agent_ip = tip.parse_ip(str(agent.get("ip") or ""))
    excluded_ips = {str(agent_ip)} if agent_ip else set()
    excluded_hosts = {
        str(v).lower() for v in (agent.get("name"), agent.get("hostname"), payload.get("hostname")) if v
    }

    ordered: List[Tuple[str, str]] = []
    if "data" in payload:
        ordered.extend(_iter_strings(payload["data"], key="data", depth=1))
    ordered.extend((k, v) for k, v in _iter_strings({k: v for k, v in payload.items() if k != "data"}))
    if isinstance(payload.get("full_log"), str):
        ordered.append(("full_log", payload["full_log"][:65536]))

    iocs: List[Dict[str, str]] = []
    seen = set()
    dropped = 0
    for key, text in ordered:
        for ioc_type, value in _scan_text(text, key, excluded_ips, excluded_hosts):
            if len(value) > MAX_IOC_LENGTH:
                continue
            ident = (ioc_type, value.lower() if ioc_type != "URL" else value)
            if ident in seen:
                continue
            seen.add(ident)
            if len(iocs) >= limit:
                dropped += 1
                continue
            iocs.append({"artifact_type": ioc_type, "value": value})
    return iocs, dropped


def extract_iocs_from_payload(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    """Backward-compatible wrapper returning only the capped IOC list."""
    return extract_iocs(payload)[0]


# ----------------------------------------------------------------------------------------
# Enrichment and dispatch
# ----------------------------------------------------------------------------------------

def enrich_indicators(iocs: List[Dict[str, str]], tip_settings: "tip.TipSettings") -> List[Dict[str, Any]]:
    """Enrich IOCs concurrently (order preserved). enrich_ioc never raises."""
    if not iocs:
        return []
    with ThreadPoolExecutor(max_workers=min(ENRICH_WORKERS, len(iocs)), thread_name_prefix="ingest-tip") as pool:
        return list(pool.map(
            lambda i: tip.tip_client.enrich_ioc(i["artifact_type"], i["value"], settings=tip_settings), iocs
        ))


def is_celery_broker_online() -> bool:
    """Short socket probe of the Celery broker."""
    try:
        parsed = urlparse(settings.CELERY_BROKER_URL)
        with socket.create_connection((parsed.hostname or "localhost", parsed.port or 6379), timeout=0.15):
            return True
    except OSError:
        return False


def dispatch_alert_processing(alert_id: int) -> str:
    """Hand the alert to the response runner. Returns "celery", "sync" or "failed"."""
    if is_celery_broker_online():
        try:
            from backend.celery_app import process_alert_task
            process_alert_task.apply_async(args=[alert_id], retry=False)
            logger.info(f"Dispatched Celery task for Alert #{alert_id}")
            return "celery"
        except Exception as e:
            logger.warning(f"Could not enqueue Celery task for Alert #{alert_id} ({e}); running synchronously.")
    try:
        from backend.engine.runner import process_alert
        process_alert(alert_id)
        return "sync"
    except Exception as e:
        logger.exception(f"Response runner failed for Alert #{alert_id}: {e}")
        return "failed"


def _summarize_verdicts(enrichments: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in enrichments:
        counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
    return counts


def _alert_identity(payload: Dict[str, Any], source: str) -> Dict[str, Any]:
    """rule_id, human description, and log target for each payload format."""
    if source in ("wazuh", "demo"):
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
        rule_id = str(rule.get("id") or payload.get("rule_id") or "WAZUH-UNKNOWN")
        description = str(rule.get("description") or f"Wazuh rule {rule_id}")
        return {"rule_id": rule_id, "description": description, "target": agent.get("name") or rule_id}

    if source == "edr":
        process = payload.get("process") if isinstance(payload.get("process"), dict) else {}
        agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
        hostname = agent.get("hostname") or agent.get("name") or payload.get("hostname")
        process_name = process.get("name") or payload.get("process_name")
        rule_id = str(payload.get("rule_id") or payload.get("alert_id") or payload.get("detection_id") or "EDR-UNSPECIFIED")
        description = str(payload.get("description") or (
            f"EDR detection: {process_name or 'unknown process'} on {hostname or 'unknown host'}"
        ))
        pid = process.get("pid")
        target = f"{hostname or 'unknown host'}" + (f" (PID {pid})" if pid is not None else "")
        return {"rule_id": rule_id, "description": description, "target": target,
                "hostname": hostname, "process_name": process_name}

    rule_id = str(payload.get("incident_id") or payload.get("id") or "XDR-UNSPECIFIED")
    layers = payload.get("correlated_layers") if isinstance(payload.get("correlated_layers"), list) else []
    tactic = payload.get("mitre_tactic")
    description = str(payload.get("description") or (
        f"XDR correlated incident{': ' + str(tactic) if tactic else ''}"
        f"{' across ' + ', '.join(map(str, layers)) if layers else ''}"
    ))
    hosts = payload.get("target") or payload.get("hosts")
    return {"rule_id": rule_id, "description": description,
            "target": str(hosts) if hosts else rule_id, "correlated_layers": layers}


@dataclass
class IngestResult:
    alert: Alert
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    iocs_dropped: int = 0
    processing: str = "sync"  # celery | sync | failed
    severity_basis: str = ""
    escalated_from: Optional[str] = None
    identity: Dict[str, Any] = field(default_factory=dict)

    @property
    def celery_dispatched(self) -> bool:
        return self.processing == "celery"


def ingest_alert_with_details(db: Session, payload: Dict[str, Any], source: str) -> IngestResult:
    """Run the full ingestion pipeline and return the alert with ingestion metadata."""
    from backend.routers.logs import record_log

    source = (source or "").strip().lower()
    if source not in SOURCES:
        raise ValueError(f"Unknown alert source '{source}'; expected one of {', '.join(SOURCES)}")
    if not isinstance(payload, dict):
        raise ValueError("Alert payload must be a JSON object")

    severity, basis = determine_severity(payload, source)
    identity = _alert_identity(payload, source)
    alert = create_alert(db, {
        "rule_id": identity["rule_id"][:100],
        "source": SOURCE_LABELS[source],
        "severity": severity,
        "status": "New",
        "raw_payload": payload,
    })

    iocs, dropped = extract_iocs(payload)
    if dropped:
        logger.warning(f"Alert #{alert.alert_id}: {dropped} indicator(s) beyond the {MAX_IOCS_PER_ALERT}-IOC cap were not stored.")
    tip_settings = tip.load_tip_settings(db)
    enrichments = enrich_indicators(iocs, tip_settings)

    artifacts = []
    for ioc, result in zip(iocs, enrichments):
        artifact = create_ioc_artifact(
            db=db,
            alert_id=alert.alert_id,
            artifact_type=ioc["artifact_type"],
            value=ioc["value"],
            threat_score=result["threat_score"],
            verdict=result["verdict"],
            enrichment_status=result["enrichment_status"],
            tip_results=result["providers"],
        )
        artifacts.append(artifact.to_dict())

    escalated_from = None
    new_severity = escalated_severity(alert.severity, (e["verdict"] for e in enrichments))
    if new_severity:
        escalated_from = alert.severity
        logger.info(f"Alert #{alert.alert_id}: severity {escalated_from} -> {new_severity} (Malicious IOC evidence).")
        alert.severity = new_severity
        db.commit()

    verdicts = _summarize_verdicts(enrichments)
    lab = source == "demo"
    received = "Lab simulation alert received (Wazuh format)" if lab else f"{SOURCE_LABELS[source]} alert received"
    level = {"Critical": "CRITICAL", "High": "ACTION"}.get(alert.severity, "WARNING")
    record_log(
        db=db,
        source=LOG_SOURCES[source],
        level=level,
        message=f"{received}: {identity['description']} (Alert #{alert.alert_id}, severity {alert.severity}).",
        target=str(identity["target"])[:200],
        details={
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "severity_basis": basis,
            "escalated_from": escalated_from,
            "ioc_count": len(artifacts),
            "iocs_dropped": dropped,
            "lab_simulation": lab,
        },
    )
    if enrichments:
        simulated = any(e["simulated"] for e in enrichments)
        summary = ", ".join(f"{n} {v}" for v, n in sorted(verdicts.items()))
        record_log(
            db=db,
            source="TIP",
            level="ACTION" if "Malicious" in verdicts else "INFO",
            message=(
                f"Threat-intel enrichment for Alert #{alert.alert_id}: {len(enrichments)} IOC(s) - {summary}."
                + (" Includes simulation-mode lab fixtures." if simulated else "")
            ),
            target=f"Alert #{alert.alert_id}",
            details={
                "alert_id": alert.alert_id,
                "verdicts": verdicts,
                "max_threat_score": max(e["threat_score"] for e in enrichments),
                "enrichment_status": {e["value"]: e["enrichment_status"] for e in enrichments},
                "lab_fixtures_used": simulated,
            },
        )

    processing = dispatch_alert_processing(alert.alert_id)
    if processing == "failed":
        record_log(
            db=db, source="AUTOMATION", level="ERROR",
            message=f"Automated triage failed for Alert #{alert.alert_id}; the alert remains in the queue for an analyst.",
            target=f"Alert #{alert.alert_id}",
        )

    db.expire_all()
    db.refresh(alert)
    return IngestResult(
        alert=alert,
        artifacts=artifacts,
        iocs_dropped=dropped,
        processing=processing,
        severity_basis=basis,
        escalated_from=escalated_from,
        identity=identity,
    )


def ingest_alert(db: Session, payload: Dict[str, Any], source: str) -> Alert:
    """Ingest one alert payload (source: wazuh | edr | xdr | demo) and return the refreshed Alert."""
    return ingest_alert_with_details(db, payload, source).alert


def reenrich_alert_iocs(db: Session, alert_id: int) -> Dict[str, Any]:
    """Re-run threat-intel enrichment for an alert's stored IOCs (e.g. after adding API keys).

    Updates each artifact's score, verdict, enrichment status and evidence. Alert severity is
    left unchanged; escalation happens only once, at ingestion.
    """
    from backend.routers.logs import record_log

    artifacts = get_ioc_artifacts_by_alert(db, alert_id)
    tip_settings = tip.load_tip_settings(db)
    enrichments = enrich_indicators(
        [{"artifact_type": a.artifact_type, "value": a.value} for a in artifacts], tip_settings
    )
    for artifact, result in zip(artifacts, enrichments):
        artifact.threat_score = result["threat_score"]
        artifact.verdict = result["verdict"]
        artifact.enrichment_status = result["enrichment_status"]
        artifact.tip_results = result["providers"]
    db.commit()

    verdicts = _summarize_verdicts(enrichments)
    max_score = max((e["threat_score"] for e in enrichments), default=0)
    record_log(
        db=db,
        source="TIP",
        level="ACTION" if "Malicious" in verdicts else "INFO",
        message=f"Threat-intel re-enrichment for Alert #{alert_id}: {len(enrichments)} IOC(s), verdicts {verdicts or 'none'}.",
        target=f"Alert #{alert_id}",
        details={"alert_id": alert_id, "verdicts": verdicts, "max_threat_score": max_score},
    )
    return {
        "alert_id": alert_id,
        "iocs_enriched": len(enrichments),
        "max_threat_score": max_score,
        "verdicts": verdicts,
        "iocs": [a.to_dict() for a in artifacts],
    }
