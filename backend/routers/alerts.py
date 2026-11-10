import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend import integration_config
from backend.config import settings
from backend.crud import (
    create_playbook_execution,
    get_alert,
    get_alerts,
    get_containment_actions_by_alert,
    get_dashboard_metrics,
    get_executions_by_alert,
    get_incident_report_by_alert,
    get_ioc_artifacts_by_alert,
)
from backend.database import SessionLocal, get_db
from backend.dependencies import (
    get_current_user,
    require_admin,
    require_analyst_or_admin,
    require_human_analyst,
)
from backend.engine import runner
from backend.engine.actions import (
    ACTION_CATALOG,
    EXECUTED_STATUSES,
    TARGET_ENTITY_KEYS,
    execute_action,
    record_policy_block,
    resolve_action_name,
)
from backend.engine.policy import evaluate_action, get_alert_entities
from backend.integrations.nvd import nvd_client
from backend.models import (
    AgentProposal,
    Alert,
    AnalystActionLog,
    ContainmentAction,
    IncidentReport,
    IocArtifact,
    PlaybookExecution,
    User,
)
from backend.schemas import AlertDecisionRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["Alerts & Cases"])

DECISIONS = {"take_action", "keep_and_monitor", "dismiss"}


def require_responder(
    current_user: User = Depends(require_human_analyst),
    _operator: User = Depends(require_analyst_or_admin),
) -> User:
    """A signed-in human with an operator role (analyst, security engineer, admin)."""
    return current_user


def _get_alert_or_404(db: Session, alert_id: int) -> Alert:
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")
    return alert


def _log_analyst_action(db: Session, alert: Alert, username: str, action_type: str, decision: str, notes: str) -> None:
    db.add(AnalystActionLog(
        alert_id=alert.alert_id,
        analyst_username=username,
        action_type=action_type,
        decision=decision,
        notes=notes,
        timestamp=datetime.now(timezone.utc),
    ))
    db.commit()


def _run_status(result: Dict[str, Any]) -> str:
    """Request-level outcome of a playbook run: never 'Success' for simulated or partial work."""
    if result.get("status") != "Contained":
        return "Incomplete"
    return "Simulated" if result.get("simulated") else "Success"


def _approve(db: Session, alert_id: int, username: str, playbook_id: Optional[int]) -> Dict[str, Any]:
    try:
        return runner.approve_and_contain_alert(db, alert_id, approved_by=username, playbook_id=playbook_id)
    except runner.NoPlaybookError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


def _reenrich_alert_task(alert_id: int) -> None:
    db = SessionLocal()
    try:
        from backend.engine.ingest import reenrich_alert_iocs
        reenrich_alert_iocs(db, alert_id)
    except Exception as exc:
        logger.error(f"Threat-intel re-enrichment for Alert #{alert_id} failed: {exc}")
    finally:
        db.close()


@router.post("/{alert_id}/enrich-background")
def trigger_background_enrichment(
    alert_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """Re-run threat-intel enrichment for the alert's IOCs in the background.

    Updates IOC scores, verdicts and evidence only; severity and containment are not re-run.
    """
    _get_alert_or_404(db, alert_id)
    background_tasks.add_task(_reenrich_alert_task, alert_id)
    return {
        "status": "Queued",
        "message": f"Threat-intel re-enrichment queued for Alert #{alert_id}.",
        "alert_id": alert_id,
    }


@router.get("/metrics/dashboard")
def get_metrics(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Aggregated SOC metrics computed from recorded alerts, executions and actions."""
    return get_dashboard_metrics(db)


@router.delete("/purge")
def purge_all_alerts(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    """Delete every alert and its artifacts, executions, actions, proposals and reports (admin only)."""
    report_paths = [r.pdf_path for r in db.query(IncidentReport).all()]
    for model in (AgentProposal, AnalystActionLog, IncidentReport, ContainmentAction, PlaybookExecution, IocArtifact):
        db.query(model).delete(synchronize_session=False)
    deleted_count = db.query(Alert).delete(synchronize_session=False)
    db.commit()

    reports_dir = os.path.realpath(settings.REPORTS_DIR)
    for path in report_paths:
        try:
            real = os.path.realpath(path)
            if real.startswith(reports_dir + os.sep) and os.path.exists(real):
                os.remove(real)
        except OSError as exc:
            logger.debug(f"Could not remove report {path}: {exc}")

    try:
        from backend.routers.logs import record_log
        record_log(db, "RBAC", "WARNING", f"{current_user.username} purged {deleted_count} alert(s) and their records.",
                   current_user.username, {"deleted_alerts": deleted_count})
    except Exception as exc:
        logger.debug(f"Could not record purge log: {exc}")

    return {
        "status": "success",
        "message": f"Purged {deleted_count} alerts and all associated records.",
        "deleted_alerts": deleted_count,
    }


@router.get("")
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List and filter alerts by severity and status."""
    alerts = get_alerts(db, skip=skip, limit=limit, severity=severity, status=status)
    result = []
    for alert in alerts:
        iocs = get_ioc_artifacts_by_alert(db, alert.alert_id)
        data = alert.to_dict()
        data["ioc_count"] = len(iocs)
        data["max_threat_score"] = max([i.threat_score for i in iocs], default=0)
        data["malicious_ioc_count"] = sum(1 for i in iocs if i.verdict == "Malicious")
        result.append(data)
    return result


@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Alert detail: IOCs with evidence, matched playbook, routing, actions, reports and an honest triage summary."""
    alert = _get_alert_or_404(db, alert_id)

    iocs = get_ioc_artifacts_by_alert(db, alert_id)
    executions = get_executions_by_alert(db, alert_id)
    actions = get_containment_actions_by_alert(db, alert_id)
    report = get_incident_report_by_alert(db, alert_id)
    playbook = runner.playbook_for_alert(db, alert)

    try:
        vulnerability_intel = nvd_client.analyze_alert_vulnerabilities(alert.to_dict())
    except Exception as exc:
        logger.warning(f"NVD analysis failed for Alert #{alert_id}: {exc}")
        vulnerability_intel = {"status": "unavailable", "error": str(exc)}

    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "source": alert.source,
        "severity": alert.severity,
        "status": alert.status,
        "analyst_decision": alert.analyst_decision,
        "assigned_analyst": alert.assigned_analyst,
        "resolved_by": alert.resolved_by,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "raw_payload": alert.raw_payload,
        "ioc_artifacts": [i.to_dict() for i in iocs],
        "playbook_executions": [e.to_dict() for e in executions],
        "containment_actions": [a.to_dict() for a in actions],
        "agent_proposals": [p.to_dict() for p in (alert.agent_proposals or [])],
        "incident_report": report.to_dict() if report else None,
        "playbook": playbook.to_dict() if playbook else None,
        "routing": runner.evaluate_execution_mode(db, alert, iocs, playbook),
        "entities": get_alert_entities(alert, iocs),
        "mitre_attack": runner.extract_mitre(alert, playbook),
        "triage_summary": runner.build_triage_summary(db, alert, iocs, playbook),
        "simulation_mode": integration_config.is_simulation_mode(db),
        "hotl_enabled": runner.is_hotl_globally_enabled(db),
        "max_threat_score": max([i.threat_score for i in iocs], default=0),
        "vulnerability_intel": vulnerability_intel,
    }


@router.get("/{alert_id}/vulnerabilities")
def get_alert_vulnerabilities(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """CVE context for the alert from the National Vulnerability Database."""
    alert = _get_alert_or_404(db, alert_id)
    return nvd_client.analyze_alert_vulnerabilities(alert.to_dict())


@router.post("/{alert_id}/vulnerabilities/execute-hotl")
def execute_cve_hotl_action(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_responder),
):
    """Run the response NVD analysis recommends (e.g. isolate a host exposed to a critical,
    network-exploitable CVE). Analyst-triggered; every target goes through policy and the
    action catalog, and the outcome is reported per target."""
    alert = _get_alert_or_404(db, alert_id)
    analysis = nvd_client.analyze_alert_vulnerabilities(alert.to_dict())
    nvd_policy = analysis.get("hotl_autonomous_policy") or {}
    action = resolve_action_name(nvd_policy.get("action_type"))
    if not nvd_policy.get("eligible_for_hotl") or action is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"message": "NVD analysis does not recommend an automated response for this alert.",
                    "nvd_policy": nvd_policy},
        )

    spec = ACTION_CATALOG[action]
    entities = get_alert_entities(alert)
    targets: List[Optional[str]] = (
        [None] if spec["target_type"] == "none" else entities.get(TARGET_ENTITY_KEYS[spec["target_type"]], [])[:5]
    )
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"NVD recommends {action}, but the alert names no {spec['target_type']} to apply it to.",
        )

    results, records = [], []
    for target in targets:
        decision = evaluate_action(db, alert, action, target, actor="analyst")
        if decision.allowed:
            record = execute_action(db, alert, action, target, executed_by=current_user.username)
        else:
            record = record_policy_block(db, alert, action, target, decision, executed_by=current_user.username)
        records.append(record)
        results.append({"policy": decision.to_dict(), "action": record.to_dict()})

    executed = [r for r in records if r.status in EXECUTED_STATUSES]
    simulated = any(r.status == "Simulated" for r in executed)
    cves = analysis.get("cves_detected") or []
    now = datetime.now(timezone.utc)
    if executed and alert.status in ("New", "Triaged", "Monitoring"):
        alert.status = "Contained"
        alert.analyst_decision = f"NVD-recommended {action}" + (f" ({cves[0]})" if cves else "")
        alert.resolved_by = current_user.username
        alert.resolved_at = now
        db.commit()
        create_playbook_execution(
            db, alert_id=alert.alert_id, playbook_id=None,
            status="Completed (NVD response, simulated)" if simulated else "Completed (NVD response)",
            mttr_seconds=runner.elapsed_seconds_since(alert.created_at),
        )
    _log_analyst_action(db, alert, current_user.username, "nvd_response", f"{action} via NVD recommendation",
                        f"{len(executed)} of {len(records)} target(s) executed")

    outcome = "Not Executed" if not executed else ("Simulated" if simulated else "Success")
    return {
        "status": outcome,
        "action_executed": action,
        "new_status": alert.status,
        "results": results,
        "nvd_policy": nvd_policy,
        "message": f"{action}: {len(executed)} of {len(records)} target(s) executed"
                   + (" (SIMULATED - no real system was changed)" if simulated else "") + ".",
    }


@router.post("/{alert_id}/decision")
def submit_analyst_decision(
    alert_id: int,
    req: AlertDecisionRequest,
    playbook_id: Optional[int] = Query(None, description="Playbook to run for take_action when none matches"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_responder),
):
    """Analyst decision on an alert:
    - take_action: run the alert's playbook (or `playbook_id`) with analyst approval.
    - keep_and_monitor: keep the alert open under monitoring; nothing is executed.
    - dismiss: close the alert.
    """
    if req.decision not in DECISIONS:
        raise HTTPException(status_code=422, detail=f"decision must be one of {sorted(DECISIONS)}")
    alert = _get_alert_or_404(db, alert_id)
    analyst = current_user.username
    now = datetime.now(timezone.utc)

    if req.decision == "take_action":
        result = _approve(db, alert_id, analyst, playbook_id)
        db.refresh(alert)
        alert.analyst_decision = f"Escalated by analyst: {result['execution_status']}"
        alert.resolved_by = analyst
        alert.resolved_at = now
        db.commit()
        _log_analyst_action(db, alert, analyst, "take_action", alert.analyst_decision,
                            req.notes or f"Ran playbook '{result['playbook']}'")
        return {
            "status": _run_status(result),
            "decision": req.decision,
            "new_status": alert.status,
            "analyst_decision": alert.analyst_decision,
            "resolved_by": analyst,
            "simulated": result["simulated"],
            "message": result["message"],
            "data": result,
            "pdf_path": result["pdf_path"],
        }

    if req.decision == "keep_and_monitor":
        alert.status = "Monitoring"
        alert.analyst_decision = "Kept as Low Risk / Continuous Monitoring"
        message = f"Alert #{alert_id} kept open under monitoring; no response action was executed."
    else:
        alert.status = "Closed"
        alert.analyst_decision = "Dismissed by Analyst"
        message = f"Alert #{alert_id} closed."
    alert.resolved_by = analyst
    alert.resolved_at = now
    db.commit()
    declined = runner.close_pending_actions(db, alert, by=analyst)
    if declined:
        message += f" {declined} action(s) awaiting approval were declined."
    db.refresh(alert)
    _log_analyst_action(db, alert, analyst, req.decision, alert.analyst_decision, req.notes or message)

    return {
        "status": "Success",
        "decision": req.decision,
        "new_status": alert.status,
        "analyst_decision": alert.analyst_decision,
        "resolved_by": analyst,
        "message": message,
    }


@router.post("/{alert_id}/approve")
def approve_alert(
    alert_id: int,
    playbook_id: Optional[int] = Query(None, description="Playbook to run when none matches the alert"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_responder),
):
    """HITL sign-off: run the matched playbook (or `playbook_id`) with the approval gate satisfied.

    409 when no playbook applies and none is given. Policy still blocks protected or invalid targets.
    """
    alert = _get_alert_or_404(db, alert_id)
    result = _approve(db, alert_id, current_user.username, playbook_id)
    db.refresh(alert)
    alert.resolved_by = current_user.username
    alert.resolved_at = datetime.now(timezone.utc)
    alert.analyst_decision = f"Approved (HITL): {result['execution_status']}"
    db.commit()
    _log_analyst_action(db, alert, current_user.username, "approve", alert.analyst_decision,
                        f"Approved playbook '{result['playbook']}'")
    return {
        "status": _run_status(result),
        "alert_status": alert.status,
        "execution_status": result["execution_status"],
        "simulated": result["simulated"],
        "message": result["message"],
        "data": result,
        "resolved_by": current_user.username,
    }


@router.post("/{alert_id}/dismiss")
def dismiss_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_responder),
):
    """Close an alert as a false positive or accepted risk."""
    alert = _get_alert_or_404(db, alert_id)
    alert.status = "Closed"
    alert.analyst_decision = "Dismissed as False Positive"
    alert.resolved_by = current_user.username
    alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    declined = runner.close_pending_actions(db, alert, by=current_user.username)
    db.refresh(alert)
    _log_analyst_action(db, alert, current_user.username, "dismiss", alert.analyst_decision, "Dismissed as False Positive")
    return {
        "status": "Success",
        "message": f"Alert #{alert_id} dismissed and closed by analyst."
                   + (f" {declined} action(s) awaiting approval were declined." if declined else ""),
        "alert_id": alert_id,
        "current_status": alert.status,
        "resolved_by": current_user.username,
    }


@router.get("/{alert_id}/report")
def stream_pdf_report(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Incident PDF, regenerated from the alert's recorded state so it is never stale."""
    alert = _get_alert_or_404(db, alert_id)
    pdf_path = runner.generate_and_save_report(db, alert)
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Failed to generate the PDF report")
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"phantom_soar_incident_report_{alert_id}.pdf",
    )
