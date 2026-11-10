from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.models import (
    Alert,
    IocArtifact,
    Playbook,
    PlaybookExecution,
    ContainmentAction,
    IncidentReport,
)
from backend.schemas import AlertCreate, PlaybookCreate, PlaybookUpdate

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

# --- IoC Artifact CRUD ---

def get_ioc_artifacts_by_alert(db: Session, alert_id: int) -> List[IocArtifact]:
    """Explicitly required: returns all IoC artifacts linked to an alert."""
    return db.query(IocArtifact).filter(IocArtifact.alert_id == alert_id).all()

def create_ioc_artifact(
    db: Session,
    alert_id: int,
    artifact_type: str,
    value: str,
    threat_score: int = 0,
    verdict: str = "Unknown",
    enrichment_status: str = "pending",
    tip_results: Optional[Dict[str, Any]] = None,
) -> IocArtifact:
    db_artifact = IocArtifact(
        alert_id=alert_id,
        artifact_type=artifact_type,
        value=value,
        threat_score=threat_score,
        verdict=verdict,
        enrichment_status=enrichment_status,
        tip_results=tip_results,
        created_at=utc_now()
    )
    db.add(db_artifact)
    db.commit()
    db.refresh(db_artifact)
    return db_artifact


# --- Alert CRUD ---

def get_alert(db: Session, alert_id: int) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.alert_id == alert_id).first()

def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None
) -> List[Alert]:
    query = db.query(Alert)
    if severity and severity.upper() != "ALL":
        query = query.filter(Alert.severity.ilike(severity))
    if status and status.upper() != "ALL":
        if status.lower() == "unresolved":
            query = query.filter(~Alert.status.in_(["Resolved", "Closed"]))
        elif status.lower() == "review":
            query = query.filter(Alert.status.in_(["Triaged", "New"]))
        else:
            query = query.filter(Alert.status.ilike(status))
    return query.order_by(desc(Alert.created_at)).offset(skip).limit(limit).all()

def create_alert(db: Session, alert_data: Any) -> Alert:
    if isinstance(alert_data, AlertCreate):
        payload_dict = alert_data.raw_payload or {}
        db_alert = Alert(
            rule_id=alert_data.rule_id,
            source=alert_data.source,
            severity=alert_data.severity,
            status=alert_data.status,
            raw_payload=payload_dict,
            created_at=utc_now()
        )
    elif isinstance(alert_data, dict):
        db_alert = Alert(
            rule_id=alert_data.get("rule_id", "WAZUH-001"),
            source=alert_data.get("source", "Wazuh"),
            severity=alert_data.get("severity", "Medium"),
            status=alert_data.get("status", "New"),
            raw_payload=alert_data.get("raw_payload", {}),
            created_at=alert_data.get("created_at", utc_now())
        )
    else:
        raise ValueError("Invalid alert data format")
    
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

def update_alert_status(db: Session, alert_id: int, status: str) -> Optional[Alert]:
    alert = get_alert(db, alert_id)
    if alert:
        alert.status = status
        db.commit()
        db.refresh(alert)
    return alert


# --- Playbook CRUD ---

def get_playbook(db: Session, playbook_id: int) -> Optional[Playbook]:
    return db.query(Playbook).filter(Playbook.playbook_id == playbook_id).first()

def get_playbook_by_threat(db: Session, target_threat: str) -> Optional[Playbook]:
    return db.query(Playbook).filter(
        Playbook.target_threat.ilike(f"%{target_threat}%"),
        Playbook.is_active == True
    ).first()

def get_playbooks(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    active_only: bool = False
) -> List[Playbook]:
    query = db.query(Playbook)
    if active_only:
        query = query.filter(Playbook.is_active == True)
    return query.order_by(Playbook.playbook_id).offset(skip).limit(limit).all()

def create_playbook(db: Session, playbook_data: Any) -> Playbook:
    if isinstance(playbook_data, PlaybookCreate):
        workflow = (
            json.dumps(playbook_data.workflow_logic)
            if not isinstance(playbook_data.workflow_logic, str)
            else playbook_data.workflow_logic
        )
        db_playbook = Playbook(
            name=playbook_data.name,
            target_threat=playbook_data.target_threat,
            execution_mode=playbook_data.execution_mode,
            workflow_logic=workflow,
            is_active=playbook_data.is_active,
            created_at=utc_now()
        )
    elif isinstance(playbook_data, dict):
        workflow = playbook_data.get("workflow_logic", {})
        if not isinstance(workflow, str):
            workflow = json.dumps(workflow)
        db_playbook = Playbook(
            name=playbook_data.get("name"),
            target_threat=playbook_data.get("target_threat"),
            execution_mode=playbook_data.get("execution_mode", "HOTL"),
            workflow_logic=workflow,
            is_active=playbook_data.get("is_active", True),
            created_at=utc_now()
        )
    else:
        raise ValueError("Invalid playbook data format")
    
    db.add(db_playbook)
    db.commit()
    db.refresh(db_playbook)
    return db_playbook

def update_playbook(db: Session, playbook_id: int, playbook_update: Any) -> Optional[Playbook]:
    playbook = get_playbook(db, playbook_id)
    if not playbook:
        return None
    
    if hasattr(playbook_update, "model_dump"):
        update_data = playbook_update.model_dump(exclude_unset=True)
    elif hasattr(playbook_update, "dict"):
        update_data = playbook_update.dict(exclude_unset=True)
    else:
        update_data = playbook_update

    if "name" in update_data and update_data["name"] is not None:
        playbook.name = update_data["name"]
    if "target_threat" in update_data and update_data["target_threat"] is not None:
        playbook.target_threat = update_data["target_threat"]
    if "execution_mode" in update_data and update_data["execution_mode"] is not None:
        playbook.execution_mode = update_data["execution_mode"]
    if "workflow_logic" in update_data and update_data["workflow_logic"] is not None:
        workflow = update_data["workflow_logic"]
        if not isinstance(workflow, str):
            workflow = json.dumps(workflow)
        playbook.workflow_logic = workflow
    if "is_active" in update_data and update_data["is_active"] is not None:
        playbook.is_active = update_data["is_active"]

    db.commit()
    db.refresh(playbook)
    return playbook

def delete_playbook(db: Session, playbook_id: int) -> bool:
    playbook = get_playbook(db, playbook_id)
    if not playbook:
        return False
    db.delete(playbook)
    db.commit()
    return True

def toggle_playbook_status(db: Session, playbook_id: int) -> Optional[Playbook]:
    playbook = get_playbook(db, playbook_id)
    if not playbook:
        return None
    playbook.is_active = not playbook.is_active
    db.commit()
    db.refresh(playbook)
    return playbook


# --- Playbook Executions & Containment Actions ---

def create_playbook_execution(
    db: Session,
    alert_id: int,
    playbook_id: Optional[int] = None,
    status: str = "Completed",
    mttr_seconds: float = 0.0
) -> PlaybookExecution:
    execution = PlaybookExecution(
        alert_id=alert_id,
        playbook_id=playbook_id,
        status=status,
        mttr_seconds=mttr_seconds,
        executed_at=utc_now()
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)
    return execution

def get_executions_by_alert(db: Session, alert_id: int) -> List[PlaybookExecution]:
    return db.query(PlaybookExecution).filter(PlaybookExecution.alert_id == alert_id).all()

def create_containment_action(
    db: Session,
    alert_id: int,
    action_type: str,
    status: str = "Executed",
    executed_by: str = "System",
    target: Optional[str] = None,
    connector: Optional[str] = None,
    execution_mode: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> ContainmentAction:
    action = ContainmentAction(
        alert_id=alert_id,
        action_type=action_type,
        status=status,
        executed_by=executed_by,
        target=target,
        connector=connector,
        execution_mode=execution_mode,
        details=details,
        timestamp=utc_now()
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action

def get_containment_actions_by_alert(db: Session, alert_id: int) -> List[ContainmentAction]:
    return db.query(ContainmentAction).filter(ContainmentAction.alert_id == alert_id).all()

def create_incident_report(
    db: Session,
    alert_id: int,
    pdf_path: str
) -> IncidentReport:
    report = IncidentReport(
        alert_id=alert_id,
        pdf_path=pdf_path,
        generated_at=utc_now()
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report

def get_incident_report_by_alert(db: Session, alert_id: int) -> Optional[IncidentReport]:
    return db.query(IncidentReport).filter(IncidentReport.alert_id == alert_id).order_by(desc(IncidentReport.generated_at)).first()


# --- Dashboard Metrics ---

def get_active_playbooks(db: Session) -> List[Playbook]:
    return db.query(Playbook).filter(Playbook.is_active == True).order_by(Playbook.playbook_id).all()  # noqa: E712

def get_dashboard_metrics(db: Session) -> Dict[str, Any]:
    """SOC metrics computed from recorded rows only.

    avg_mttr_seconds averages executions that actually contained an alert (mttr_seconds > 0)
    and is None when there are none; mttr_sample_size says how many runs it covers.
    automated_actions counts actions that ran live or simulated; the per-mode counts say which.
    """
    total_alerts = db.query(Alert).count()
    new_alerts = db.query(Alert).filter(Alert.status == "New").count()
    triaged_alerts = db.query(Alert).filter(Alert.status == "Triaged").count()
    contained_alerts = db.query(Alert).filter(Alert.status == "Contained").count()
    resolved_alerts = db.query(Alert).filter(Alert.status.in_(["Resolved", "Closed"])).count()
    unresolved_alerts = db.query(Alert).filter(~Alert.status.in_(["Resolved", "Closed"])).count()
    review_gates_count = db.query(Alert).filter(Alert.status.in_(["Triaged", "New"])).count()

    mode_counts = dict(
        db.query(ContainmentAction.execution_mode, func.count(ContainmentAction.action_id))
        .group_by(ContainmentAction.execution_mode)
        .all()
    )
    live_actions = int(mode_counts.get("live", 0))
    simulated_actions = int(mode_counts.get("simulated", 0))

    mttr_avg, mttr_count = (
        db.query(func.avg(PlaybookExecution.mttr_seconds), func.count(PlaybookExecution.execution_id))
        .filter(PlaybookExecution.mttr_seconds > 0)
        .one()
    )

    critical_count = db.query(Alert).filter(Alert.severity == "Critical").count()
    high_count = db.query(Alert).filter(Alert.severity == "High").count()
    medium_count = db.query(Alert).filter(Alert.severity == "Medium").count()
    low_count = db.query(Alert).filter(Alert.severity == "Low").count()

    return {
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "triaged_alerts": triaged_alerts,
        "contained_alerts": contained_alerts,
        "resolved_alerts": resolved_alerts,
        "unresolved_alerts": unresolved_alerts,
        "review_gates_count": review_gates_count,
        "automated_actions": live_actions + simulated_actions,
        "live_actions": live_actions,
        "simulated_actions": simulated_actions,
        "blocked_actions": int(mode_counts.get("blocked", 0)),
        "failed_actions": int(mode_counts.get("failed", 0)),
        "skipped_actions": int(mode_counts.get("skipped", 0)),
        "avg_mttr_seconds": round(float(mttr_avg), 2) if mttr_count else None,
        "mttr_sample_size": int(mttr_count or 0),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count
    }
