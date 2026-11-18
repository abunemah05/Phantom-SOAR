"""Alert ingestion pipeline shared by the SIEM / EDR / XDR webhooks and the lab demo.

ingest_alert() turns a raw payload into an Alert:
  1. severity from the telemetry itself (Wazuh rule.level, or the EDR/XDR "severity" field)
  2. IOC extraction (IPv4/IPv6, MD5/SHA-1/SHA-256, domains, URLs), de-duplicated and capped
  3. the alert and its IOCs (verdict "Unknown", status "pending") are saved and a telemetry log
     entry is written, so the webhook can answer quickly
  4. enrich_and_process_alert (a Celery task when a broker accepts it, otherwise run inline):
     threat-intel enrichment of every IOC, at most one step of severity escalation (never above
     High, only for a Malicious verdict backed by live or lab-fixture evidence; Unknown never
     escalates), then the response runner
  5. IOCs whose enrichment came back incomplete / rate limited are re-enriched later by a delayed
     Celery task (max 3 attempts); results update the stored artifacts
"""
import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from backend.config import settings
from backend.crud import create_alert, create_ioc_artifact, get_alert, get_ioc_artifacts_by_alert
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

_DEFANG_SUBS = (
    (re.compile(r"\bhxxp(s?)\b", re.IGNORECASE), r"http\1"),
    (re.compile(r"\bfxp(s?)\b", re.IGNORECASE), r"ftp\1"),
    (re.compile(r"\[\s*://\s*\]|\(\s*://\s*\)"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.IGNORECASE), "."),
    (re.compile(r"\[\s*(?:@|at)\s*\]|\(\s*at\s*\)", re.IGNORECASE), "@"),
)


def refang(text: str) -> str:
    """Undo common defanging (hxxp://, example[.]com, 1[.]2[.]3[.]4, [:]/[://], [@]) so the real
    indicator is extracted and looked up. The value is only ever queried, never contacted."""
    for pattern, replacement in _DEFANG_SUBS:
        text = pattern.sub(replacement, text)
    return text

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
    text = refang(text)
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
    iocs, dropped_iocs = extract_iocs_detailed(payload, limit)
    return iocs, len(dropped_iocs)


def extract_iocs_detailed(payload: Dict[str, Any], limit: int = MAX_IOCS_PER_ALERT) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Like extract_iocs, but returns the dropped indicators themselves instead of a count."""
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
    dropped: List[Dict[str, str]] = []
    for key, text in ordered:
        for ioc_type, value in _scan_text(text, key, excluded_ips, excluded_hosts):
            if len(value) > MAX_IOC_LENGTH:
                continue
            ident = (ioc_type, value.lower() if ioc_type != "URL" else value)
            if ident in seen:
                continue
            seen.add(ident)
            if len(iocs) >= limit:
                dropped.append({"artifact_type": ioc_type, "value": value})
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


# Re-enrichment of IOCs whose providers were rate limited (threat-intel engineer's contract:
# provider status "rate_limited" with retry_after_seconds, and a result-level ``incomplete`` flag).
REENRICH_MAX_ATTEMPTS = 3
REENRICH_DEFAULT_DELAY = 60
REENRICH_MIN_DELAY = 5
REENRICH_MAX_DELAY = 300  # far below the broker visibility timeout, which holds countdown tasks

# Enqueue policy: bounded kombu publish retry so a brief broker blip does not force inline mode.
_ENQUEUE_RETRY_POLICY = {"max_retries": 2, "interval_start": 0.1, "interval_step": 0.3, "interval_max": 0.6}


def is_celery_broker_online() -> bool:
    """Open (and close) a real broker connection with a bounded retry. Informational only:
    dispatch never relies on this, it relies on the outcome of the actual enqueue."""
    try:
        from backend.celery_app import celery_app
        with celery_app.connection_for_write() as conn:
            conn.ensure_connection(max_retries=1, interval_start=0.1, interval_step=0.2, timeout=3)
        return True
    except Exception:
        return False


def _enqueue(task, args: List[Any], countdown: Optional[int] = None) -> bool:
    """Publish a Celery task. True only when the broker accepted the message.

    Any exception from apply_async means no message was acknowledged by the broker, so the caller
    may fall back to inline processing without risking a second run. (In the rare case a message
    was published and the acknowledgement lost, the tasks are idempotent: process_alert claims the
    alert atomically, enrichment skips finished IOCs and escalation is computed from the payload.)
    """
    try:
        # ignore_result: nothing waits on these tasks (the database is the source of truth), and
        # without it apply_async also subscribes to the result backend, which retries ~20 s and can
        # wedge the long-lived web process if Redis blips.
        kwargs: Dict[str, Any] = {"args": args, "retry": True, "retry_policy": _ENQUEUE_RETRY_POLICY,
                                  "ignore_result": True}
        if countdown:
            kwargs["countdown"] = int(countdown)
        task.apply_async(**kwargs)
        return True
    except Exception as exc:
        logger.warning(f"Could not enqueue {getattr(task, 'name', task)} {args}: {type(exc).__name__}: {exc}")
        return False


def dispatch_alert_processing(alert_id: int) -> str:
    """Hand the alert to enrichment + the response runner. Returns "celery", "sync" or "failed".

    The Celery task is tried first; the inline run happens only when enqueueing failed, so the work
    is never started twice from here.
    """
    try:
        from backend.celery_app import enrich_and_process_alert_task
    except Exception as exc:  # pragma: no cover - celery import problems
        logger.warning(f"Celery unavailable ({exc}); running Alert #{alert_id} inline.")
    else:
        if _enqueue(enrich_and_process_alert_task, [alert_id]):
            logger.info(f"Dispatched enrichment/processing task for Alert #{alert_id}")
            return "celery"
        logger.warning(f"No broker accepted the task for Alert #{alert_id}; running inline.")
    try:
        enrich_and_process_alert(alert_id)
        return "sync"
    except Exception as exc:
        logger.exception(f"Enrichment/response runner failed for Alert #{alert_id}: {exc}")
        return "failed"


# ----------------------------------------------------------------------------------------
# Incomplete enrichment helpers
# ----------------------------------------------------------------------------------------

def _provider_results(result: Dict[str, Any]) -> Dict[str, Any]:
    providers = result.get("providers")
    return providers if isinstance(providers, dict) else {}


def result_is_incomplete(result: Dict[str, Any]) -> bool:
    """True when a provider was rate limited or the result is flagged ``incomplete``."""
    if result.get("incomplete"):
        return True
    return any(isinstance(p, dict) and p.get("status") == "rate_limited" for p in _provider_results(result).values())


def result_retry_delay(result: Dict[str, Any]) -> int:
    """Seconds to wait before re-enriching: the longest retry_after_seconds, clamped."""
    hints = []
    for p in _provider_results(result).values():
        if isinstance(p, dict) and p.get("status") == "rate_limited":
            try:
                hints.append(float(p.get("retry_after_seconds")))
            except (TypeError, ValueError):
                pass
    try:
        hints.append(float(result.get("retry_after_seconds")))
    except (TypeError, ValueError):
        pass
    delay = max(hints) if hints else REENRICH_DEFAULT_DELAY
    return int(min(REENRICH_MAX_DELAY, max(REENRICH_MIN_DELAY, delay)))


def _apply_enrichment(artifact, result: Dict[str, Any]) -> None:
    artifact.threat_score = result["threat_score"]
    artifact.verdict = result["verdict"]
    artifact.enrichment_status = result["enrichment_status"]
    artifact.tip_results = result["providers"]


# ----------------------------------------------------------------------------------------
# Severity escalation (idempotent)
# ----------------------------------------------------------------------------------------

_SOURCE_BY_LABEL = {label: key for key, label in SOURCE_LABELS.items()}


def baseline_severity(alert: Alert) -> Optional[str]:
    """Severity the telemetry itself implies (before any escalation), or None if unknowable."""
    source = _SOURCE_BY_LABEL.get(alert.source)
    if not source or not isinstance(alert.raw_payload, dict):
        return None
    return determine_severity(alert.raw_payload, source)[0]


def escalate_once(db: Session, alert: Alert, verdicts: Iterable[str]) -> Optional[str]:
    """Escalate the alert one step on a Malicious verdict; at most once, however often it is called.

    The target is computed from the telemetry baseline and applied with a conditional UPDATE
    (``severity = baseline``), so repeated or concurrent calls (task redelivery, re-enrichment)
    cannot escalate twice, and an analyst-changed severity is never overwritten.
    Returns the previous severity when this call escalated, else None.
    """
    baseline = baseline_severity(alert)
    if baseline is None:
        return None
    target = escalated_severity(baseline, verdicts)
    if target is None:
        return None
    changed = (
        db.query(Alert)
        .filter(Alert.alert_id == alert.alert_id, Alert.severity == baseline)
        .update({"severity": target}, synchronize_session=False)
    )
    db.commit()
    if not changed:
        return None
    db.refresh(alert)
    logger.info(f"Alert #{alert.alert_id}: severity {baseline} -> {target} (Malicious IOC evidence).")
    return baseline


def _log_escalation(db: Session, alert: Alert, previous: str, source_key: str, delayed: bool = False) -> None:
    from backend.routers.logs import record_log

    record_log(
        db=db, source=LOG_SOURCES.get(source_key, "SIEM"),
        level="CRITICAL" if alert.severity == "Critical" else "ACTION",
        message=(
            f"Alert #{alert.alert_id} severity escalated {previous} -> {alert.severity} on Malicious threat-intel evidence"
            + (" (found by delayed re-enrichment)." if delayed else ".")
        ),
        target=f"Alert #{alert.alert_id}",
        details={"alert_id": alert.alert_id, "escalated_from": previous, "severity": alert.severity, "delayed": delayed},
    )


def _summarize_verdicts(enrichments: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in enrichments:
        counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
    return counts


def _log_enrichment(db: Session, alert_id: int, enrichments: List[Dict[str, Any]], incomplete: int, scheduled: bool) -> None:
    from backend.routers.logs import record_log

    verdicts = _summarize_verdicts(enrichments)
    simulated = any(e.get("simulated") for e in enrichments)
    summary = ", ".join(f"{n} {v}" for v, n in sorted(verdicts.items()))
    note = ""
    if incomplete:
        note = (f" {incomplete} IOC(s) were rate limited or incomplete; re-enrichment "
                + ("scheduled." if scheduled else "could not be scheduled (no worker), use Re-enrich."))
    record_log(
        db=db,
        source="TIP",
        level="ACTION" if "Malicious" in verdicts else ("WARNING" if incomplete else "INFO"),
        message=(
            f"Threat-intel enrichment for Alert #{alert_id}: {len(enrichments)} IOC(s) - {summary}."
            + (" Includes simulation-mode lab fixtures." if simulated else "") + note
        ),
        target=f"Alert #{alert_id}",
        details={
            "alert_id": alert_id,
            "verdicts": verdicts,
            "max_threat_score": max(e["threat_score"] for e in enrichments),
            "enrichment_status": {e["value"]: e["enrichment_status"] for e in enrichments},
            "lab_fixtures_used": simulated,
            "incomplete_iocs": incomplete,
            "reenrichment_scheduled": scheduled,
        },
    )


def schedule_reenrichment(alert_id: int, artifact_ids: List[int], countdown: int, attempt: int) -> bool:
    """Queue re_enrich_iocs_task after ``countdown`` seconds. False when no broker accepted it."""
    try:
        from backend.celery_app import re_enrich_iocs_task
    except Exception:  # pragma: no cover
        return False
    return _enqueue(re_enrich_iocs_task, [alert_id, list(artifact_ids), attempt], countdown=countdown)


# ----------------------------------------------------------------------------------------
# Enrichment + processing (run by the Celery task, or inline when there is no broker)
# ----------------------------------------------------------------------------------------

def enrich_and_process_alert(alert_id: int) -> Dict[str, Any]:
    """Enrich the alert's pending IOCs, escalate once on Malicious evidence, route the alert.

    Idempotent: only IOCs still "pending" are enriched, escalation is conditional, and
    process_alert claims the alert atomically, so a redelivered task repeats nothing.
    """
    from backend.database import SessionLocal

    db = SessionLocal()
    try:
        alert = get_alert(db, alert_id)
        if not alert:
            logger.error(f"Alert #{alert_id} not found; nothing to enrich.")
            return {"status": "Error", "message": f"Alert {alert_id} not found"}

        pending = [a for a in get_ioc_artifacts_by_alert(db, alert_id) if a.enrichment_status == "pending"]
        enrichments: List[Dict[str, Any]] = []
        escalated_from = None
        if pending:
            enrichments = enrich_indicators(
                [{"artifact_type": a.artifact_type, "value": a.value} for a in pending], tip.load_tip_settings(db)
            )
            for artifact, result in zip(pending, enrichments):
                _apply_enrichment(artifact, result)
            db.commit()

            incomplete = [(a, r) for a, r in zip(pending, enrichments) if result_is_incomplete(r)]
            scheduled = False
            if incomplete:
                countdown = max(result_retry_delay(r) for _, r in incomplete)
                scheduled = schedule_reenrichment(alert_id, [a.artifact_id for a, _ in incomplete], countdown, 1)
            _log_enrichment(db, alert_id, enrichments, len(incomplete), scheduled)

            escalated_from = escalate_once(db, alert, (e["verdict"] for e in enrichments))
            if escalated_from:
                _log_escalation(db, alert, escalated_from, _SOURCE_BY_LABEL.get(alert.source, "wazuh"))
        db.close()
        db = None

        from backend.engine.runner import process_alert
        outcome = process_alert(alert_id)
        return {"alert_id": alert_id, "iocs_enriched": len(enrichments), "escalated_from": escalated_from,
                "processing": outcome}
    finally:
        if db is not None:
            db.close()


def re_enrich_incomplete_iocs(alert_id: int, artifact_ids: List[int], attempt: int = 1) -> Dict[str, Any]:
    """Delayed re-enrichment of IOCs that were rate limited the first time.

    Updates the stored artifacts; still-incomplete ones are rescheduled (max REENRICH_MAX_ATTEMPTS
    attempts in total). If a Malicious verdict appears, severity escalates once and the alert is
    routed (process_alert is a no-op when it was already processed).
    """
    from backend.database import SessionLocal

    db = SessionLocal()
    try:
        alert = get_alert(db, alert_id)
        if not alert:
            return {"status": "Error", "message": f"Alert {alert_id} not found"}
        wanted = set(artifact_ids)
        artifacts = [a for a in get_ioc_artifacts_by_alert(db, alert_id) if a.artifact_id in wanted]
        if not artifacts:
            return {"alert_id": alert_id, "iocs_enriched": 0, "still_incomplete": 0}

        results = enrich_indicators(
            [{"artifact_type": a.artifact_type, "value": a.value} for a in artifacts], tip.load_tip_settings(db)
        )
        for artifact, result in zip(artifacts, results):
            _apply_enrichment(artifact, result)
        db.commit()

        still = [(a, r) for a, r in zip(artifacts, results) if result_is_incomplete(r)]
        rescheduled = False
        if still and attempt < REENRICH_MAX_ATTEMPTS:
            rescheduled = schedule_reenrichment(
                alert_id, [a.artifact_id for a, _ in still], max(result_retry_delay(r) for _, r in still), attempt + 1
            )
        _log_enrichment(db, alert_id, results, len(still), rescheduled)
        if still and not rescheduled:
            logger.warning(f"Alert #{alert_id}: {len(still)} IOC(s) remain incomplete after attempt {attempt}; giving up.")

        verdicts = [a.verdict for a in get_ioc_artifacts_by_alert(db, alert_id)]
        escalated_from = escalate_once(db, alert, verdicts)
        if escalated_from:
            _log_escalation(db, alert, escalated_from, _SOURCE_BY_LABEL.get(alert.source, "wazuh"), delayed=True)
        malicious = "Malicious" in verdicts
    finally:
        db.close()

    processing = None
    if malicious:
        from backend.engine.runner import process_alert
        processing = process_alert(alert_id)  # no-op if the alert was already processed
    return {"alert_id": alert_id, "iocs_enriched": len(results), "still_incomplete": len(still),
            "rescheduled": rescheduled, "escalated_from": escalated_from, "processing": processing}


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

    @property
    def enrichment_pending(self) -> bool:
        """True when enrichment runs in a background worker (artifacts are still "pending")."""
        return self.processing == "celery"


def ingest_alert_with_details(db: Session, payload: Dict[str, Any], source: str) -> IngestResult:
    """Save the alert and its IOCs, then hand enrichment + processing to a worker (or run inline).

    Returns as soon as the alert is stored and the task is queued. With no reachable broker the
    enrichment and response runner run inline, so artifacts in the result are already enriched.
    """
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

    iocs, dropped_iocs = extract_iocs_detailed(payload)
    dropped = len(dropped_iocs)
    for ioc in iocs:
        create_ioc_artifact(
            db=db, alert_id=alert.alert_id, artifact_type=ioc["artifact_type"], value=ioc["value"],
            threat_score=0, verdict="Unknown", enrichment_status="pending", tip_results=None,
        )
    if dropped:
        logger.warning(f"Alert #{alert.alert_id}: {dropped} indicator(s) beyond the {MAX_IOCS_PER_ALERT}-IOC cap were not stored.")
        record_log(
            db=db, source=LOG_SOURCES[source], level="WARNING",
            message=(f"Alert #{alert.alert_id}: {dropped} indicator(s) exceeded the {MAX_IOCS_PER_ALERT}-IOC limit and were "
                     "not enriched; review the raw payload for the rest."),
            target=f"Alert #{alert.alert_id}",
            details={"alert_id": alert.alert_id, "iocs_dropped": dropped, "ioc_cap": MAX_IOCS_PER_ALERT,
                     "dropped_sample": dropped_iocs[:25]},
        )

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
            "ioc_count": len(iocs),
            "iocs_dropped": dropped,
            "lab_simulation": lab,
        },
    )

    alert_id = alert.alert_id
    processing = dispatch_alert_processing(alert_id)
    if processing == "failed":
        record_log(
            db=db, source="AUTOMATION", level="ERROR",
            message=f"Automated triage failed for Alert #{alert_id}; the alert remains in the queue for an analyst.",
            target=f"Alert #{alert_id}",
        )

    db.expire_all()
    db.refresh(alert)
    artifacts = [a.to_dict() for a in get_ioc_artifacts_by_alert(db, alert_id)]
    escalated_from = severity if alert.severity != severity else None
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
