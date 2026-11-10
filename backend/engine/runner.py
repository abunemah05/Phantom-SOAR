"""Alert orchestration: playbook matching, HOTL / HITL routing and step execution.

process_alert(alert_id) is called once per ingested alert (by Celery or
synchronously). It matches a playbook, then either runs the playbook's steps
autonomously (HOTL) or parks the alert for analyst approval (HITL).

HOTL requires all of:
  * the global HOTL switch (ORCHESTRATION.hotl_enabled) is on,
  * the matched playbook's execution_mode is HOTL,
  * real evidence: an IOC whose verdict is Malicious backed by live or lab
    threat intelligence, or Critical telemetry severity.
Unknown evidence never triggers autonomous containment.

Every step goes through policy.evaluate_action(actor="playbook") and then
actions.execute_action, and every outcome (including policy blocks) is
recorded as a ContainmentAction. MTTR is the real time from alert creation to
the end of the run that contained it.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend import integration_config
from backend.crud import (
    create_containment_action,
    create_incident_report,
    create_playbook_execution,
    get_alert,
    get_ioc_artifacts_by_alert,
    get_playbook,
)
from backend.database import SessionLocal
from backend.engine.actions import (
    ACTION_CATALOG,
    CONTAINMENT_CONNECTORS,
    EXECUTED_STATUSES,
    TARGET_ENTITY_KEYS,
    alert_agent,
    execute_action,
    pseudo_step_kind,
    record_policy_block,
    resolve_action_name,
)
from backend.engine.playbooks_catalog import TEMPLATES_BY_NAME
from backend.engine.policy import evaluate_action, get_alert_entities
from backend.engine.reporter import generate_pdf_report
from backend.models import Alert, IncidentReport, Playbook, PlaybookExecution

logger = logging.getLogger(__name__)

MAX_TARGETS_PER_STEP = 5
EVIDENCE_STATUSES = {"live", "lab_fixture"}
HOTL_ENGINE = "HOTL Engine"


class NoPlaybookError(ValueError):
    """Raised when an approval is requested but no playbook applies to the alert."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def elapsed_seconds_since(created_at: Optional[datetime]) -> float:
    start = _as_utc(created_at)
    if start is None:
        return 0.0
    return round(max((utc_now() - start).total_seconds(), 0.0), 2)


def is_hotl_globally_enabled(db: Optional[Session] = None) -> bool:
    """Global HOTL kill switch (ORCHESTRATION.hotl_enabled; default on)."""
    return integration_config.get_bool("hotl_enabled", db=db)


# --- Playbook matching --------------------------------------------------------

def parse_workflow(playbook: Optional[Playbook]) -> Dict[str, Any]:
    if playbook is None:
        return {}
    workflow = playbook.workflow_logic
    if isinstance(workflow, str):
        try:
            workflow = json.loads(workflow)
        except (TypeError, ValueError):
            return {}
    return workflow if isinstance(workflow, dict) else {}


def _rule(alert: Alert) -> Dict[str, Any]:
    raw = alert.raw_payload or {}
    return raw.get("rule") if isinstance(raw.get("rule"), dict) else {}


def _alert_text(alert: Alert) -> str:
    raw = alert.raw_payload or {}
    rule = _rule(alert)
    parts = [alert.rule_id or "", str(rule.get("description") or "")]
    groups = rule.get("groups")
    if isinstance(groups, list):
        parts.extend(str(g) for g in groups)
    for key in ("title", "description", "threat_name", "detection_name", "mitre_tactic", "category", "full_log"):
        if isinstance(raw.get(key), str):
            parts.append(raw[key])
    return " ".join(parts).replace("_", " ").lower()


def _alert_mitre_ids(alert: Alert) -> List[str]:
    raw = alert.raw_payload or {}
    mitre = _rule(alert).get("mitre")
    ids: List[str] = []
    if isinstance(mitre, dict):
        value = mitre.get("id")
        ids.extend(value if isinstance(value, list) else [value] if value else [])
    for key in ("mitre_technique", "mitre_id"):
        value = raw.get(key)
        if isinstance(value, list):
            ids.extend(value)
        elif isinstance(value, str):
            ids.append(value)
    return [str(i).strip().upper() for i in ids if i and str(i).strip().upper().startswith("T")]


def _playbook_keywords(playbook: Playbook, workflow: Dict[str, Any]) -> List[str]:
    keywords = workflow.get("keywords")
    if not isinstance(keywords, list):
        template = TEMPLATES_BY_NAME.get(playbook.name, {})
        keywords = template.get("workflow_logic", {}).get("keywords", [])
    return [playbook.target_threat or ""] + [str(k) for k in keywords]


def match_playbook(db: Session, alert: Alert) -> Optional[Playbook]:
    """Best active playbook for the alert, by MITRE technique and threat keywords; None if nothing matches."""
    text = _alert_text(alert)
    mitre_ids = set(_alert_mitre_ids(alert))
    mitre_bases = {m.split(".")[0] for m in mitre_ids}

    best, best_score = None, 0
    playbooks = db.query(Playbook).filter(Playbook.is_active == True).order_by(Playbook.playbook_id).all()  # noqa: E712
    for playbook in playbooks:
        workflow = parse_workflow(playbook)
        score = 0
        pb_mitre = str(workflow.get("mitre_id") or "").strip().upper()
        if pb_mitre and pb_mitre in mitre_ids:
            score += 3
        elif pb_mitre and pb_mitre.split(".")[0] in mitre_bases:
            score += 2
        if any(k and k.lower() in text for k in _playbook_keywords(playbook, workflow)):
            score += 2
        if score > best_score:
            best, best_score = playbook, score
    return best


def executed_playbook(db: Session, alert: Alert) -> Optional[Playbook]:
    """The playbook most recently routed/executed for this alert, if any."""
    execution = (
        db.query(PlaybookExecution)
        .filter(PlaybookExecution.alert_id == alert.alert_id, PlaybookExecution.playbook_id.isnot(None))
        .order_by(PlaybookExecution.execution_id.desc())
        .first()
    )
    return execution.playbook if execution else None


def playbook_for_alert(db: Session, alert: Alert) -> Optional[Playbook]:
    return executed_playbook(db, alert) or match_playbook(db, alert)


# --- Evidence and routing -----------------------------------------------------

def _provider_results(ioc: Any) -> Dict[str, Dict[str, Any]]:
    results = getattr(ioc, "tip_results", None)
    if not isinstance(results, dict):
        return {}
    providers = results.get("providers") if isinstance(results.get("providers"), dict) else results
    return {name: p for name, p in providers.items() if isinstance(p, dict) and "status" in p}


def ioc_evidence_sources(ioc: Any) -> List[str]:
    """Providers whose live or lab-fixture result produced a score for this IOC."""
    return sorted(
        str(p.get("provider") or name)
        for name, p in _provider_results(ioc).items()
        if p.get("status") in EVIDENCE_STATUSES and p.get("threat_score") is not None
    )


def ioc_evidence_kind(ioc: Any) -> Optional[str]:
    """"lab fixture" when every scored result is a lab fixture, "live" when any is live, else None."""
    statuses = {
        p.get("status") for p in _provider_results(ioc).values() if p.get("threat_score") is not None
    } & EVIDENCE_STATUSES
    if not statuses:
        return None
    return "lab fixture" if statuses == {"lab_fixture"} else "live"


def collect_evidence(alert: Alert, iocs: List[Any]) -> List[str]:
    evidence = []
    for ioc in iocs:
        if (ioc.verdict or "") != "Malicious":
            continue
        kind = ioc_evidence_kind(ioc)
        if kind is None:
            continue
        label = "lab fixture" if kind == "lab fixture" else "live threat intelligence"
        evidence.append(f"{ioc.artifact_type} {ioc.value} is Malicious per {label} ({', '.join(ioc_evidence_sources(ioc))})")
    if (alert.severity or "").capitalize() == "Critical":
        evidence.append("Telemetry severity is Critical")
    return evidence


def evaluate_execution_mode(
    db: Optional[Session], alert: Alert, iocs: List[Any], playbook: Optional[Playbook]
) -> Dict[str, Any]:
    """Route an alert to HOTL or HITL. Returns {"mode", "reasons", "evidence"}."""
    evidence = collect_evidence(alert, iocs)
    if playbook is None:
        return {"mode": "HITL", "evidence": evidence,
                "reasons": ["No active playbook matches this alert; analyst triage required."]}
    if not is_hotl_globally_enabled(db):
        return {"mode": "HITL", "evidence": evidence,
                "reasons": ["Autonomous response (HOTL) is switched off globally; analyst approval required."]}
    if (playbook.execution_mode or "").upper() != "HOTL":
        return {"mode": "HITL", "evidence": evidence,
                "reasons": [f"Playbook '{playbook.name}' is configured for analyst approval (HITL)."]}
    if not evidence:
        return {"mode": "HITL", "evidence": evidence, "reasons": [
            "No confirmed evidence: no IOC has a Malicious verdict from live or lab threat intelligence "
            "and telemetry severity is not Critical. Analyst review required."
        ]}
    return {"mode": "HOTL", "evidence": evidence,
            "reasons": [f"Playbook '{playbook.name}' is HOTL and the alert has confirmed evidence."]}


# --- Step execution -----------------------------------------------------------

def playbook_steps(playbook: Optional[Playbook]) -> List[Dict[str, Any]]:
    steps = parse_workflow(playbook).get("steps")
    if not isinstance(steps, list):
        return []

    def order(step: Dict[str, Any]) -> int:
        value = step.get("order", step.get("step"))
        return value if isinstance(value, int) else 0

    return sorted((s for s in steps if isinstance(s, dict)), key=order)


def _step_targets(action: Optional[str], alert: Alert, iocs: List[Any], entities: Dict[str, List[str]]) -> List[Optional[str]]:
    if action is None:
        return [None]
    target_type = ACTION_CATALOG[action]["target_type"]
    if target_type == "none":
        return [None]
    values = list(entities.get(TARGET_ENTITY_KEYS[target_type], []))
    if target_type == "ip":
        # Never aim IP containment at the monitored host itself or at IPs threat intel calls clean.
        own_ip = alert_agent(alert).get("ip")
        clean = {str(i.value) for i in iocs if (i.artifact_type or "").upper() == "IP" and i.verdict == "Clean"}
        values = [v for v in values if v != own_ip and v not in clean]
    return values[:MAX_TARGETS_PER_STEP]


def _record_key(action: str, target: Optional[str], alert: Alert) -> tuple:
    if ACTION_CATALOG.get(action, {}).get("target_type") == "none":
        return (action, f"Alert #{alert.alert_id}")
    return (action, (target or "").lower())


def run_playbook_steps(
    db: Session,
    alert: Alert,
    playbook: Playbook,
    iocs: List[Any],
    executed_by: str,
    approved: bool,
    stop_at_gate: bool,
) -> Dict[str, Any]:
    """Execute a playbook's steps for an alert. Steps already executed for the alert are not repeated."""
    entities = get_alert_entities(alert, iocs)
    existing = list(alert.containment_actions or [])
    done = {_record_key(ca.action_type, ca.target, alert) for ca in existing if ca.status in EXECUTED_STATUSES}
    held = {}
    for ca in existing:
        if ca.status == "Awaiting Approval":
            held.setdefault(_record_key(ca.action_type, ca.target, alert), []).append(ca)
    records, notes, reused = [], [], []
    paused_at_gate = None

    for index, step in enumerate(playbook_steps(playbook), start=1):
        name = step.get("action")
        kind = pseudo_step_kind(name)
        if kind == "gate":
            if stop_at_gate:
                paused_at_gate = index
                notes.append(f"Step {index}: paused at the analyst approval gate.")
                break
            notes.append(f"Step {index}: approval gate satisfied by {executed_by}.")
            continue
        if kind == "enrichment":
            notes.append(f"Step {index}: {name} - IOC enrichment already ran at ingestion.")
            continue
        if kind == "report":
            notes.append(f"Step {index}: incident report is generated when the run completes.")
            continue

        canonical = resolve_action_name(name)
        params = step.get("params") if isinstance(step.get("params"), dict) else {}
        if canonical:
            allowed_params = ACTION_CATALOG[canonical].get("params", {})
            ignored = sorted(k for k in params if k not in allowed_params)
            if ignored:
                notes.append(f"Step {index}: ignored unsupported params {ignored} for {canonical}.")
            params = {k: v for k, v in params.items() if k in allowed_params}

        targets = _step_targets(canonical, alert, iocs, entities)
        if not targets:
            target_type = ACTION_CATALOG[canonical]["target_type"]
            records.append(create_containment_action(
                db, alert.alert_id, canonical, status="Skipped", executed_by=executed_by,
                target=None, connector=ACTION_CATALOG[canonical]["connector"], execution_mode="skipped",
                details={"reason": "no_target", "message": f"The alert names no {target_type} for {canonical}."},
            ))
            continue

        for target in targets:
            if canonical and _record_key(canonical, target, alert) in done:
                reused.append({"action": canonical, "target": target})
                continue
            decision = evaluate_action(db, alert, canonical or name, target, params, actor="playbook")
            if not decision.allowed or (decision.requires_approval and not approved):
                records.append(record_policy_block(db, alert, canonical or str(name), target, decision, executed_by, params))
                continue
            record = execute_action(db, alert, canonical, target, params, executed_by=executed_by)
            records.append(record)
            key = _record_key(canonical, target, alert)
            done.add(key)
            approved_holds = held.pop(key, [])
            for pending in approved_holds:
                _resolve_held(pending, "Approved", executed_by, record.action_id)
            if approved_holds:
                db.commit()

    return {"records": records, "notes": notes, "already_done": reused, "paused_at_gate": paused_at_gate}


def _resolve_held(record: Any, status: str, by: str, action_id: Optional[int] = None) -> None:
    details = dict(record.details or {})
    details["resolution"] = {"status": status, "by": by, "at": utc_now().isoformat(), "executed_action_id": action_id}
    record.status = status
    record.details = details


def close_pending_actions(db: Session, alert: Alert, by: str, status: str = "Declined") -> int:
    """Mark actions still awaiting approval as declined (alert dismissed or kept under monitoring)."""
    pending = [ca for ca in (alert.containment_actions or []) if ca.status == "Awaiting Approval"]
    for record in pending:
        _resolve_held(record, status, by)
    if pending:
        db.commit()
    return len(pending)


def _classify_run(run: Dict[str, Any], mode: str) -> Dict[str, Any]:
    records = run["records"]
    containment_ok = [
        r for r in records if r.connector in CONTAINMENT_CONNECTORS and r.status in EXECUTED_STATUSES
    ]
    reused_ok = [
        r for r in run["already_done"] if ACTION_CATALOG.get(r["action"], {}).get("connector") in CONTAINMENT_CONNECTORS
    ]
    awaiting = [r for r in records if r.status == "Awaiting Approval"]
    problems = [
        r for r in records
        if r.status in ("Failed", "Blocked")
        or (r.status == "Skipped" and (r.details or {}).get("reason") != "no_target")
    ]
    simulated = any(r.status == "Simulated" for r in records)
    suffix = ", simulated" if simulated else ""

    if run["paused_at_gate"] or awaiting:
        return {"alert_status": "Triaged", "execution_status": f"Awaiting Approval ({mode})", "simulated": simulated}
    if not containment_ok and not reused_ok:
        return {"alert_status": "Triaged", "execution_status": f"No Containment ({mode})", "simulated": simulated}
    if problems:
        return {"alert_status": "Contained", "execution_status": f"Partial ({mode}{suffix})", "simulated": simulated}
    return {"alert_status": "Contained", "execution_status": f"Completed ({mode}{suffix})", "simulated": simulated}


def _upsert_execution(db: Session, alert: Alert, playbook: Optional[Playbook], status: str, mttr: float) -> PlaybookExecution:
    pending = (
        db.query(PlaybookExecution)
        .filter(PlaybookExecution.alert_id == alert.alert_id, PlaybookExecution.status.like("Pending%"))
        .order_by(PlaybookExecution.execution_id.desc())
        .first()
    )
    if pending:
        pending.playbook_id = playbook.playbook_id if playbook else pending.playbook_id
        pending.status = status
        pending.mttr_seconds = mttr
        pending.executed_at = utc_now()
        db.commit()
        db.refresh(pending)
        return pending
    return create_playbook_execution(
        db, alert_id=alert.alert_id, playbook_id=playbook.playbook_id if playbook else None,
        status=status, mttr_seconds=mttr,
    )


def _log(db: Session, level: str, message: str, alert: Alert, details: Dict[str, Any]) -> None:
    try:
        from backend.routers.logs import record_log
        record_log(db, "AUTOMATION", level, message, f"Alert #{alert.alert_id}", details)
    except Exception as exc:
        logger.debug(f"Could not record automation log: {exc}")
        db.rollback()


def _finish_run(
    db: Session, alert: Alert, playbook: Playbook, run: Dict[str, Any], mode: str
) -> Dict[str, Any]:
    outcome = _classify_run(run, mode)
    alert.status = outcome["alert_status"]
    db.commit()
    db.refresh(alert)

    mttr = elapsed_seconds_since(alert.created_at) if alert.status == "Contained" else 0.0
    execution = _upsert_execution(db, alert, playbook, outcome["execution_status"], mttr)
    pdf_path = generate_and_save_report(db, alert)

    _log(
        db, "ACTION" if alert.status == "Contained" else "WARNING",
        f"Playbook '{playbook.name}' ({mode}) on Alert #{alert.alert_id}: {outcome['execution_status']}"
        + (f", MTTR {mttr}s" if mttr else ""),
        alert,
        {"alert_id": alert.alert_id, "playbook_id": playbook.playbook_id, "mode": mode,
         "execution_status": outcome["execution_status"], "notes": run["notes"],
         "actions": [r.action_id for r in run["records"]]},
    )
    return {
        "status": alert.status,
        "mode": mode,
        "alert_id": alert.alert_id,
        "playbook": playbook.name,
        "execution_status": execution.status,
        "simulated": outcome["simulated"],
        "mttr_seconds": mttr if mttr else None,
        "pdf_path": pdf_path,
        "notes": run["notes"],
        "already_done": run["already_done"],
        "actions": [r.to_dict() for r in run["records"]],
    }


# --- Entry points -------------------------------------------------------------

def process_alert(alert_id: int) -> Dict[str, Any]:
    """Route a newly ingested alert: run its HOTL playbook autonomously or park it for HITL approval."""
    db = SessionLocal()
    try:
        alert = get_alert(db, alert_id)
        if not alert:
            logger.error(f"Alert #{alert_id} not found in database.")
            return {"status": "Error", "message": f"Alert {alert_id} not found"}
        if alert.status != "New":
            return {"status": alert.status, "mode": None, "alert_id": alert_id,
                    "message": "Alert was already processed; nothing was re-run."}

        iocs = get_ioc_artifacts_by_alert(db, alert_id)
        playbook = match_playbook(db, alert)
        routing = evaluate_execution_mode(db, alert, iocs, playbook)
        logger.info(f"[SOAR Runner] Alert #{alert_id}: playbook={playbook.name if playbook else None} -> {routing['mode']}")
        _log(
            db, "INFO",
            f"Alert #{alert_id} routed to {routing['mode']}"
            + (f" with playbook '{playbook.name}'" if playbook else " (no matching playbook)")
            + ": " + " ".join(routing["reasons"]),
            alert,
            {"alert_id": alert_id, "playbook_id": playbook.playbook_id if playbook else None, **routing},
        )

        if routing["mode"] == "HOTL":
            run = run_playbook_steps(
                db, alert, playbook, iocs, executed_by=HOTL_ENGINE, approved=False, stop_at_gate=True
            )
            result = _finish_run(db, alert, playbook, run, "HOTL")
            result.update({"reasons": routing["reasons"], "evidence": routing["evidence"]})
            return result

        alert.status = "Triaged"
        db.commit()
        create_playbook_execution(
            db,
            alert_id=alert.alert_id,
            playbook_id=playbook.playbook_id if playbook else None,
            status="Pending Analyst Approval" if playbook else "Pending Analyst Triage",
            mttr_seconds=0.0,
        )
        return {
            "status": "Triaged",
            "mode": "HITL",
            "alert_id": alert_id,
            "playbook": playbook.name if playbook else None,
            "reasons": routing["reasons"],
            "evidence": routing["evidence"],
            "action": "Awaiting analyst approval",
        }
    finally:
        db.close()


def approve_and_contain_alert(
    db: Session,
    alert_id: int,
    approved_by: str = "Analyst",
    playbook_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Analyst sign-off: run the alert's playbook (approval gates satisfied) and record the outcome.

    Raises ValueError when the alert or the requested playbook does not exist, and
    NoPlaybookError when no playbook applies and none was chosen.
    """
    alert = get_alert(db, alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")

    if playbook_id is not None:
        playbook = get_playbook(db, playbook_id)
        if playbook is None:
            raise ValueError(f"Playbook {playbook_id} not found")
    else:
        playbook = playbook_for_alert(db, alert)
    if playbook is None:
        raise NoPlaybookError(
            f"No playbook matches Alert #{alert_id}; choose a playbook_id or respond with individual actions."
        )

    iocs = get_ioc_artifacts_by_alert(db, alert_id)
    run = run_playbook_steps(db, alert, playbook, iocs, executed_by=approved_by, approved=True, stop_at_gate=False)
    result = _finish_run(db, alert, playbook, run, "HITL")
    result["approved_by"] = approved_by
    result["message"] = (
        f"Playbook '{playbook.name}' executed for Alert #{alert_id} after approval by {approved_by}: "
        f"{result['execution_status']}."
    )
    return result


# --- Triage summary, MITRE mapping and reporting -------------------------------

def extract_mitre(alert: Alert, playbook: Optional[Playbook]) -> Dict[str, Any]:
    """MITRE ATT&CK mapping from the telemetry's rule.mitre, else the playbook's mitre_id; never guessed."""
    mitre = _rule(alert).get("mitre")
    if isinstance(mitre, dict) and mitre.get("id"):
        def as_list(value: Any) -> List[str]:
            if value is None:
                return []
            return [str(v) for v in value] if isinstance(value, list) else [str(value)]
        return {"id": as_list(mitre.get("id")), "tactic": as_list(mitre.get("tactic")),
                "technique": as_list(mitre.get("technique")), "source": "telemetry"}

    workflow = parse_workflow(playbook)
    if workflow.get("mitre_id"):
        tactic = workflow.get("mitre_tactic")
        technique = workflow.get("mitre_technique")
        return {"id": [str(workflow["mitre_id"])], "tactic": [tactic] if tactic else [],
                "technique": [technique] if technique else [], "source": "playbook"}
    return {"id": [], "tactic": [], "technique": [], "source": None}


def build_triage_summary(db: Session, alert: Alert, iocs: List[Any], playbook: Optional[Playbook]) -> str:
    """Plain, rule-based account of what is known about the alert and what the platform did."""
    rule = _rule(alert)
    title = rule.get("description") or (alert.raw_payload or {}).get("title") or alert.rule_id
    parts = [f"{alert.source} alert {alert.rule_id}: {title}. Severity {alert.severity}."]

    if iocs:
        counts: Dict[str, int] = {}
        for ioc in iocs:
            counts[ioc.verdict or "Unknown"] = counts.get(ioc.verdict or "Unknown", 0) + 1
        verdicts = ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
        parts.append(f"{len(iocs)} indicator(s) extracted ({verdicts}).")
        unenriched = sum(1 for i in iocs if (i.enrichment_status or "") in ("not_configured", "unavailable", "pending"))
        if unenriched:
            parts.append(f"{unenriched} indicator(s) could not be checked against threat intelligence.")
    else:
        parts.append("No indicators were extracted.")

    evidence = collect_evidence(alert, iocs)
    if evidence:
        parts.append("Evidence: " + "; ".join(evidence) + ".")

    if playbook:
        parts.append(f"Playbook: '{playbook.name}' ({(playbook.execution_mode or 'HITL').upper()}).")
    else:
        parts.append("No active playbook matches this alert.")

    actions = list(alert.containment_actions or [])
    if actions:
        modes: Dict[str, int] = {}
        for action in actions:
            modes[action.execution_mode or "n/a"] = modes.get(action.execution_mode or "n/a", 0) + 1
        parts.append(
            f"{len(actions)} response action record(s): "
            + ", ".join(f"{n} {m}" for m, n in sorted(modes.items())) + "."
        )
        if modes.get("simulated"):
            parts.append("Simulated actions were not executed against any real system.")
    elif alert.status in ("New", "Triaged"):
        routing = evaluate_execution_mode(db, alert, iocs, playbook)
        parts.append("No response actions yet. " + " ".join(routing["reasons"]))

    parts.append(f"Current status: {alert.status}.")
    return " ".join(parts)


def describe_execution_mode(db: Session, alert: Alert) -> str:
    execution = (
        db.query(PlaybookExecution)
        .filter(PlaybookExecution.alert_id == alert.alert_id)
        .order_by(PlaybookExecution.execution_id.desc())
        .first()
    )
    if execution is None:
        return "Not processed by a playbook"
    label = execution.status
    if "(HITL" in label and alert.resolved_by:
        label += f" - approved by {alert.resolved_by}"
    return label


def latest_mttr(db: Session, alert: Alert) -> Optional[float]:
    execution = (
        db.query(PlaybookExecution)
        .filter(PlaybookExecution.alert_id == alert.alert_id, PlaybookExecution.mttr_seconds > 0)
        .order_by(PlaybookExecution.execution_id.desc())
        .first()
    )
    return execution.mttr_seconds if execution else None


def build_report_payload(db: Session, alert: Alert) -> Dict[str, Any]:
    iocs = get_ioc_artifacts_by_alert(db, alert.alert_id)
    playbook = playbook_for_alert(db, alert)
    actions = sorted(alert.containment_actions or [], key=lambda a: a.action_id)
    created = _as_utc(alert.created_at)
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "source": alert.source,
        "severity": alert.severity,
        "status": alert.status,
        "created_at": created.isoformat() if created else None,
        "mttr_seconds": latest_mttr(db, alert),
        "execution_mode": describe_execution_mode(db, alert),
        "threat_name": _rule(alert).get("description") or alert.rule_id,
        "playbook_name": playbook.name if playbook else None,
        "mitre_attack": extract_mitre(alert, playbook),
        "triage_summary": build_triage_summary(db, alert, iocs, playbook),
        "simulation_mode": integration_config.is_simulation_mode(db),
        "analyst_decision": alert.analyst_decision,
        "resolved_by": alert.resolved_by,
        "ioc_artifacts": [
            {
                "artifact_type": i.artifact_type,
                "value": i.value,
                "threat_score": i.threat_score,
                "verdict": i.verdict,
                "enrichment_status": i.enrichment_status,
                "evidence_sources": ioc_evidence_sources(i),
                "evidence_kind": ioc_evidence_kind(i),
            }
            for i in iocs
        ],
        "containment_actions": [
            {
                "action_type": a.action_type,
                "status": a.status,
                "target": a.target,
                "connector": a.connector,
                "execution_mode": a.execution_mode,
                "executed_by": a.executed_by,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "error": (a.details or {}).get("error"),
                "reasons": (a.details or {}).get("reasons"),
            }
            for a in actions
        ],
    }


def generate_and_save_report(
    db: Session,
    alert: Alert,
    iocs: Optional[List[Any]] = None,
    mttr_seconds: Optional[float] = None,
    execution_mode: Optional[str] = None,
) -> str:
    """Render the incident PDF from the alert's recorded state and register it in IncidentReports.

    iocs / mttr_seconds / execution_mode are accepted for older callers; the report is always
    built from the database so it never disagrees with what was recorded.
    """
    payload = build_report_payload(db, alert)
    pdf_path = generate_pdf_report(payload)
    existing = db.query(IncidentReport).filter(IncidentReport.alert_id == alert.alert_id).first()
    if existing:
        existing.pdf_path = pdf_path
        existing.generated_at = utc_now()
        db.commit()
    else:
        create_incident_report(db, alert.alert_id, pdf_path)
    return pdf_path
