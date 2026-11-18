"""Alert orchestration: playbook matching, HOTL / HITL routing and step execution.

process_alert(alert_id) is called once per ingested alert (by Celery or
synchronously). It matches a playbook, then either runs the playbook's steps
autonomously (HOTL) or parks the alert for analyst approval (HITL).

HOTL requires all of:
  * the global HOTL switch (ORCHESTRATION.hotl_enabled, default OFF) is on,
  * the matched playbook's execution_mode is HOTL, and the playbook was
    selected by a strong signal (MITRE id, or the sender's rule description /
    groups), never by keywords in free-text log fields alone,
  * real evidence: an IOC whose verdict is Malicious backed by LIVE provider
    data (lab_fixture results count only while simulation mode is on).
Telemetry severity is NOT evidence: for EDR/XDR sources it is whatever the
sender writes. Unknown evidence never triggers autonomous containment.

Every step goes through policy.evaluate_action(actor="playbook") and then
actions.execute_action, and every outcome (including policy blocks) is
recorded as a ContainmentAction. MTTR is the real time from alert creation to
the end of the run that really contained it.

Alert status vocabulary: New -> Processing (claimed, lease held) -> Triaged
(awaiting analyst), Contained (at least one LIVE containment action
succeeded), Simulated (only simulated actions ran: nothing is contained) ->
Resolved / Closed / Monitoring (analyst). A simulated action never counts as
done: repeating the run after the connector is configured performs it for real.

Idempotency: process_alert claims the alert with a single atomic
UPDATE ... WHERE status='New' and holds a lease (a PlaybookExecution row with
status 'Running' whose executed_at is the lease time). A concurrent call or a
Celery redelivery cannot claim it; a claim older than LEASE_SECONDS is stale
and may be reclaimed, resuming the run while skipping actions that already
have a live Success record.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
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
    TARGET_ENTITY_KEYS,
    alert_agent,
    execute_action,
    is_live_success,
    pseudo_step_kind,
    record_policy_block,
    resolve_action_name,
)
from backend.engine.playbooks_catalog import TEMPLATES_BY_NAME
from backend.engine.policy import evaluate_action, get_alert_entities
from backend.engine.reporter import generate_pdf_report
from backend.models import Alert, ContainmentAction, IncidentReport, Playbook, PlaybookExecution

logger = logging.getLogger(__name__)

MAX_TARGETS_PER_STEP = 5
EVIDENCE_STATUSES = {"live", "lab_fixture"}
HOTL_ENGINE = "HOTL Engine"
LEASE_SECONDS = 600  # a Processing claim older than this is stale and may be reclaimed
STATUS_PROCESSING = "Processing"
LEASE_RUNNING = "Running"


class NoPlaybookError(ValueError):
    """Raised when an approval is requested but no playbook applies to the alert."""


class AlertBusyError(ValueError):
    """Raised when another worker or analyst holds a fresh claim on the alert (map to HTTP 409)."""


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
    """Global HOTL kill switch (ORCHESTRATION.hotl_enabled; default OFF)."""
    return integration_config.hotl_effective(db)


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


def _norm(text: str) -> str:
    return text.replace("_", " ").lower()


def _alert_signal_text(alert: Alert) -> str:
    """Text from the sender's rule / detection fields: a strong signal for playbook selection."""
    raw = alert.raw_payload or {}
    rule = _rule(alert)
    parts = [alert.rule_id or "", str(rule.get("description") or "")]
    groups = rule.get("groups")
    if isinstance(groups, list):
        parts.extend(str(g) for g in groups)
    for key in ("title", "description", "threat_name", "detection_name", "mitre_tactic", "category"):
        if isinstance(raw.get(key), str):
            parts.append(raw[key])
    return _norm(" ".join(parts))


def _alert_freetext(alert: Alert) -> str:
    """Free-text telemetry (full_log): attacker-influenced, so a weak signal only."""
    raw = alert.raw_payload or {}
    return _norm(raw["full_log"]) if isinstance(raw.get("full_log"), str) else ""


def _alert_text(alert: Alert) -> str:
    return (_alert_signal_text(alert) + " " + _alert_freetext(alert)).strip()


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
    """Best active playbook for the alert; None if nothing matches.

    Signals, strongest first: MITRE id from the sender's rule (exact 4, technique family 3),
    keywords in the rule description / groups / detection fields (2), keywords in free-text
    full_log (1, attacker-influenced). Ranking is by strong score, then weak score. A HOTL
    playbook is never selected on weak signals alone, so log text cannot steer the alert
    into an autonomous playbook.
    """
    strong_text = _alert_signal_text(alert)
    weak_text = _alert_freetext(alert)
    mitre_ids = set(_alert_mitre_ids(alert))
    mitre_bases = {m.split(".")[0] for m in mitre_ids}

    best, best_key = None, (0, 0)
    playbooks = db.query(Playbook).filter(Playbook.is_active == True).order_by(Playbook.playbook_id).all()  # noqa: E712
    for playbook in playbooks:
        workflow = parse_workflow(playbook)
        strong = weak = 0
        pb_mitre = str(workflow.get("mitre_id") or "").strip().upper()
        if pb_mitre and pb_mitre in mitre_ids:
            strong += 4
        elif pb_mitre and pb_mitre.split(".")[0] in mitre_bases:
            strong += 3
        keywords = [k.lower() for k in _playbook_keywords(playbook, workflow) if k]
        if any(k in strong_text for k in keywords):
            strong += 2
        if any(k in weak_text for k in keywords):
            weak += 1
        if strong == 0 and (weak == 0 or (playbook.execution_mode or "").upper() == "HOTL"):
            continue
        if (strong, weak) > best_key:
            best, best_key = playbook, (strong, weak)
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


def ioc_evidence_sources(ioc: Any, allow_lab: bool = True) -> List[str]:
    """Providers whose live (or, if allow_lab, lab-fixture) result produced a score for this IOC."""
    accepted = EVIDENCE_STATUSES if allow_lab else {"live"}
    return sorted(
        str(p.get("provider") or name)
        for name, p in _provider_results(ioc).items()
        if p.get("status") in accepted and p.get("threat_score") is not None
    )


def ioc_evidence_kind(ioc: Any, allow_lab: bool = True) -> Optional[str]:
    """"lab fixture" when every scored result is a lab fixture, "live" when any is live, else None."""
    accepted = EVIDENCE_STATUSES if allow_lab else {"live"}
    statuses = {
        p.get("status") for p in _provider_results(ioc).values() if p.get("threat_score") is not None
    } & accepted
    if not statuses:
        return None
    return "lab fixture" if statuses == {"lab_fixture"} else "live"


def collect_evidence(alert: Alert, iocs: List[Any], db: Optional[Session] = None) -> List[str]:
    """Confirmed evidence for autonomous action: Malicious IOCs backed by live provider data.

    Lab-fixture results count only while simulation mode is on. Telemetry severity is
    never evidence: for EDR/XDR sources it is supplied by the sender.
    """
    allow_lab = integration_config.is_simulation_mode(db)
    evidence = []
    for ioc in iocs:
        if (ioc.verdict or "") != "Malicious":
            continue
        kind = ioc_evidence_kind(ioc, allow_lab=allow_lab)
        if kind is None:
            continue
        label = "lab fixture" if kind == "lab fixture" else "live threat intelligence"
        sources = ", ".join(ioc_evidence_sources(ioc, allow_lab=allow_lab))
        evidence.append(f"{ioc.artifact_type} {ioc.value} is Malicious per {label} ({sources})")
    return evidence


def evaluate_execution_mode(
    db: Optional[Session], alert: Alert, iocs: List[Any], playbook: Optional[Playbook]
) -> Dict[str, Any]:
    """Route an alert to HOTL or HITL. Returns {"mode", "reasons", "evidence"}."""
    evidence = collect_evidence(alert, iocs, db)
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
            "No confirmed evidence: no IOC has a Malicious verdict backed by live threat intelligence "
            "(sender-supplied severity is not evidence). Analyst review required."
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


def _step_targets(action: Optional[str], alert: Alert, iocs: List[Any], entities: Dict[str, List[str]],
                  approved: bool = False) -> List[Optional[str]]:
    if action is None:
        return [None]
    target_type = ACTION_CATALOG[action]["target_type"]
    if target_type == "none":
        return [None]
    values = list(entities.get(TARGET_ENTITY_KEYS[target_type], []))
    if target_type == "ip":
        # Never aim IP containment at the monitored host itself or at IPs threat intel calls clean.
        own_ip = alert_agent(alert).get("ip")
        # An automated block must rest on evidence: only IPs that threat intel calls Malicious are targeted. Other
        # IPs in the payload (attacker-influenced log text can contain anyone's address) are never blocked here.
        # An analyst-approved run has been reviewed by a human, so it keeps every non-clean IP.
        clean = {str(i.value) for i in iocs if (i.artifact_type or "").upper() == "IP" and i.verdict == "Clean"}
        malicious = {str(i.value) for i in iocs if (i.artifact_type or "").upper() == "IP" and i.verdict == "Malicious"}
        values = [v for v in values if v != own_ip and v not in clean and (approved or v in malicious)]
    return values[:MAX_TARGETS_PER_STEP]


def _alert_has_entities(entities: Dict[str, List[str]], target_type: str) -> bool:
    return bool(entities.get(TARGET_ENTITY_KEYS.get(target_type, ""), []))


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
    # Only a LIVE Success is done. Simulated, Failed, Skipped and Blocked records are redone.
    done = _live_done_keys(db, alert, existing)
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

        targets = _step_targets(canonical, alert, iocs, entities, approved=approved)
        if not targets:
            target_type = ACTION_CATALOG[canonical]["target_type"]
            records.append(create_containment_action(
                db, alert.alert_id, canonical, status="Skipped", executed_by=executed_by,
                target=None, connector=ACTION_CATALOG[canonical]["connector"], execution_mode="skipped",
                details={"reason": "no_target", "message": (
                    f"No {target_type} target for {canonical}: "
                    + ("the alert names none." if not _alert_has_entities(entities, target_type)
                       else f"none of the alert's {target_type}s has a Malicious verdict, so nothing is acted on "
                            "without analyst approval.")
                )},
            ))
            continue

        for target in targets:
            if canonical:
                done |= _live_done_keys(db, alert)  # another worker may have executed it meanwhile
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


def _live_done_keys(db: Session, alert: Alert, records: Optional[List[Any]] = None) -> set:
    if records is None:
        db.expire_all()
        records = db.query(ContainmentAction).filter(ContainmentAction.alert_id == alert.alert_id).all()
    return {
        _record_key(ca.action_type, ca.target, alert)
        for ca in records if is_live_success(ca.status, ca.execution_mode)
    }


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
    """Alert and execution status for a run.

    Contained requires at least one LIVE containment success (this run or an earlier one).
    A run whose containment actions all merely simulated ends as "Simulated": nothing is contained.
    """
    records = run["records"]
    containment_ok = [
        r for r in records if r.connector in CONTAINMENT_CONNECTORS and is_live_success(r.status, r.execution_mode)
    ]
    containment_sim = [r for r in records if r.connector in CONTAINMENT_CONNECTORS and r.status == "Simulated"]
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
        if containment_sim:
            status = f"Partial ({mode}, simulated)" if problems else f"Simulated ({mode})"
            return {"alert_status": "Simulated", "execution_status": status, "simulated": True}
        return {"alert_status": "Triaged", "execution_status": f"No Containment ({mode})", "simulated": simulated}
    if problems:
        return {"alert_status": "Contained", "execution_status": f"Partial ({mode}{suffix})", "simulated": simulated}
    return {"alert_status": "Contained", "execution_status": f"Completed ({mode}{suffix})", "simulated": simulated}


def _upsert_execution(
    db: Session, alert: Alert, playbook: Optional[Playbook], status: str, mttr: float,
    lease_id: Optional[int] = None,
) -> PlaybookExecution:
    """Record the run's outcome on its lease row, else on the pending approval row, else a new row."""
    row = None
    if lease_id is not None:
        row = db.query(PlaybookExecution).filter(PlaybookExecution.execution_id == lease_id).first()
    if row is None:
        row = (
            db.query(PlaybookExecution)
            .filter(PlaybookExecution.alert_id == alert.alert_id, PlaybookExecution.status.like("Pending%"))
            .order_by(PlaybookExecution.execution_id.desc())
            .first()
        )
    if row:
        row.playbook_id = playbook.playbook_id if playbook else row.playbook_id
        row.status = status
        row.mttr_seconds = mttr
        row.executed_at = utc_now()
        db.commit()
        db.refresh(row)
        return row
    return create_playbook_execution(
        db, alert_id=alert.alert_id, playbook_id=playbook.playbook_id if playbook else None,
        status=status, mttr_seconds=mttr,
    )


# --- Claiming (idempotency) ---------------------------------------------------

def _claim_alert(db: Session, alert_id: int, expected_status: str) -> Optional[int]:
    """Atomically move the alert from expected_status to Processing and open a Running lease.

    A single UPDATE ... WHERE status=expected is the compare-and-swap: of any number of
    racing callers exactly one sees rowcount == 1. The lease row is created in the same
    transaction. Returns the lease (PlaybookExecution) id, or None when the claim was lost.
    """
    try:
        claimed = (
            db.query(Alert)
            .filter(Alert.alert_id == alert_id, Alert.status == expected_status)
            .update({Alert.status: STATUS_PROCESSING}, synchronize_session=False)
        )
        if claimed != 1:
            db.rollback()
            return None
        # An analyst-approval row left by routing is adopted as the lease so one run = one row.
        lease = (
            db.query(PlaybookExecution)
            .filter(PlaybookExecution.alert_id == alert_id, PlaybookExecution.status.like("Pending%"))
            .order_by(PlaybookExecution.execution_id.desc())
            .first()
        )
        if lease is not None:
            lease.status, lease.executed_at = LEASE_RUNNING, utc_now()
        else:
            lease = PlaybookExecution(
                alert_id=alert_id, playbook_id=None, status=LEASE_RUNNING, mttr_seconds=0.0, executed_at=utc_now()
            )
            db.add(lease)
        db.commit()
        lease_id = lease.execution_id
    except Exception:
        db.rollback()
        raise
    db.expire_all()
    return lease_id


def _reclaim_stale(db: Session, alert_id: int) -> Optional[int]:
    """Take over a Processing alert whose lease is older than LEASE_SECONDS (compare-and-swap on the lease time)."""
    lease = (
        db.query(PlaybookExecution)
        .filter(PlaybookExecution.alert_id == alert_id, PlaybookExecution.status == LEASE_RUNNING)
        .order_by(PlaybookExecution.execution_id.desc())
        .first()
    )
    if lease is None:
        return None
    seen = lease.executed_at
    age = (utc_now() - (_as_utc(seen) or utc_now())).total_seconds()
    if age < LEASE_SECONDS:
        return None
    won = (
        db.query(PlaybookExecution)
        .filter(
            PlaybookExecution.execution_id == lease.execution_id,
            PlaybookExecution.status == LEASE_RUNNING,
            PlaybookExecution.executed_at == seen,
        )
        .update({PlaybookExecution.executed_at: utc_now()}, synchronize_session=False)
    )
    db.commit()
    db.expire_all()
    return lease.execution_id if won == 1 else None


def _release_claim(db: Session, alert_id: int, lease_id: Optional[int], back_to: str) -> None:
    """After an unexpected error: hand the alert back so a retry can claim it (finished actions are skipped)."""
    try:
        db.rollback()
        db.query(Alert).filter(Alert.alert_id == alert_id, Alert.status == STATUS_PROCESSING).update(
            {Alert.status: back_to}, synchronize_session=False
        )
        if lease_id is not None:
            db.query(PlaybookExecution).filter(
                PlaybookExecution.execution_id == lease_id, PlaybookExecution.status == LEASE_RUNNING
            ).update({PlaybookExecution.status: "Interrupted"}, synchronize_session=False)
        db.commit()
    except Exception as exc:
        logger.error(f"Could not release claim on Alert #{alert_id}: {exc}")
        db.rollback()


def resume_stale_alerts(limit: int = 50) -> List[int]:
    """Re-run alerts stuck in Processing past the lease (worker died). For a periodic Celery beat task."""
    db = SessionLocal()
    try:
        cutoff = utc_now() - timedelta(seconds=LEASE_SECONDS)
        ids = [
            row.alert_id for row in db.query(PlaybookExecution)
            .join(Alert, Alert.alert_id == PlaybookExecution.alert_id)
            .filter(Alert.status == STATUS_PROCESSING, PlaybookExecution.status == LEASE_RUNNING,
                    PlaybookExecution.executed_at < cutoff.replace(tzinfo=None))
            .limit(limit).all()
        ]
    finally:
        db.close()
    for alert_id in ids:
        try:
            process_alert(alert_id)
        except Exception as exc:
            logger.error(f"Resuming stale Alert #{alert_id} failed: {exc}")
    return ids


def _log(db: Session, level: str, message: str, alert: Alert, details: Dict[str, Any]) -> None:
    try:
        from backend.routers.logs import record_log
        record_log(db, "AUTOMATION", level, message, f"Alert #{alert.alert_id}", details)
    except Exception as exc:
        logger.debug(f"Could not record automation log: {exc}")
        db.rollback()


def _finish_run(
    db: Session, alert: Alert, playbook: Playbook, run: Dict[str, Any], mode: str, lease_id: Optional[int] = None
) -> Dict[str, Any]:
    outcome = _classify_run(run, mode)
    alert.status = outcome["alert_status"]
    db.commit()
    db.refresh(alert)

    mttr = elapsed_seconds_since(alert.created_at) if alert.status == "Contained" else 0.0
    execution = _upsert_execution(db, alert, playbook, outcome["execution_status"], mttr, lease_id=lease_id)
    pdf_path = generate_and_save_report(db, alert)

    _log(
        db, "ACTION" if alert.status == "Contained" else "WARNING",
        f"Playbook '{playbook.name}' ({mode}) on Alert #{alert.alert_id}: {outcome['execution_status']}"
        + (f", MTTR {mttr}s" if mttr else "")
        + (" - NOT contained: only simulated actions ran" if alert.status == "Simulated" else ""),
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

def _acquire_for_processing(db: Session, alert_id: int) -> Optional[int]:
    """Claim a New alert, or reclaim a stale Processing one. None when someone else holds it."""
    lease_id = _claim_alert(db, alert_id, "New")
    if lease_id is None:
        lease_id = _reclaim_stale(db, alert_id)
        if lease_id is not None:
            logger.warning(f"[SOAR Runner] Alert #{alert_id}: reclaimed a stale Processing claim; resuming.")
    return lease_id


def process_alert(alert_id: int) -> Dict[str, Any]:
    """Route a newly ingested alert: run its HOTL playbook autonomously or park it for HITL approval.

    Idempotent: the alert is claimed atomically (New -> Processing), so concurrent calls and
    Celery redeliveries never execute an action twice.
    """
    db = SessionLocal()
    lease_id: Optional[int] = None
    try:
        alert = get_alert(db, alert_id)
        if not alert:
            logger.error(f"Alert #{alert_id} not found in database.")
            return {"status": "Error", "message": f"Alert {alert_id} not found"}

        lease_id = _acquire_for_processing(db, alert_id)
        if lease_id is None:
            db.expire_all()
            alert = get_alert(db, alert_id)
            busy = alert.status == STATUS_PROCESSING
            return {"status": alert.status, "mode": None, "alert_id": alert_id, "busy": busy,
                    "message": ("Alert is being processed by another worker; nothing was re-run." if busy
                                else "Alert was already processed; nothing was re-run.")}

        try:
            alert = get_alert(db, alert_id)
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
                result = _finish_run(db, alert, playbook, run, "HOTL", lease_id=lease_id)
                result.update({"reasons": routing["reasons"], "evidence": routing["evidence"]})
                return result

            alert.status = "Triaged"
            db.commit()
            _upsert_execution(
                db, alert, playbook,
                "Pending Analyst Approval" if playbook else "Pending Analyst Triage", 0.0, lease_id=lease_id,
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
        except Exception:
            # Hand the alert back so a retry can claim it; actions with a live Success are never repeated.
            _release_claim(db, alert_id, lease_id, back_to="New")
            raise
    finally:
        db.close()


def approve_and_contain_alert(
    db: Session,
    alert_id: int,
    approved_by: str = "Analyst",
    playbook_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Analyst sign-off: run the alert's playbook (approval gates satisfied) and record the outcome.

    Also the way to redo a "Simulated" alert for real once connectors are configured.
    Raises ValueError when the alert or the requested playbook does not exist,
    NoPlaybookError when no playbook applies and none was chosen, and AlertBusyError
    when another worker holds a fresh claim on the alert.
    """
    alert = get_alert(db, alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")
    db.refresh(alert)  # the claim below compares against the status as stored, not a cached copy

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

    previous = alert.status
    if previous == STATUS_PROCESSING:
        lease_id = _reclaim_stale(db, alert_id)
        previous = "Triaged"
    else:
        lease_id = _claim_alert(db, alert_id, previous)
    if lease_id is None:
        raise AlertBusyError(f"Alert #{alert_id} is being processed by another worker; try again shortly.")

    try:
        alert = get_alert(db, alert_id)
        iocs = get_ioc_artifacts_by_alert(db, alert_id)
        run = run_playbook_steps(db, alert, playbook, iocs, executed_by=approved_by, approved=True, stop_at_gate=False)
        result = _finish_run(db, alert, playbook, run, "HITL", lease_id=lease_id)
    except Exception:
        _release_claim(db, alert_id, lease_id, back_to=previous)
        raise
    result["approved_by"] = approved_by
    result["message"] = (
        f"Playbook '{playbook.name}' executed for Alert #{alert_id} after approval by {approved_by}: "
        f"{result['execution_status']}."
        + (" Only simulated actions ran: the alert is NOT contained." if result["status"] == "Simulated" else "")
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

    evidence = collect_evidence(alert, iocs, db)
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
        if alert.status == "Simulated":
            parts.append("The alert is NOT contained: only simulated actions ran. Configure the connectors, "
                         "turn simulation off and re-run the playbook.")
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
