import os
import logging
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.database import get_db, SessionLocal
from backend.models import (
    Alert, 
    AnalystActionLog, 
    User, 
    SystemLog, 
    IocArtifact, 
    PlaybookExecution, 
    ContainmentAction, 
    IncidentReport
)
from backend.crud import (
    get_alert,
    get_alerts,
    get_ioc_artifacts_by_alert,
    get_executions_by_alert,
    get_containment_actions_by_alert,
    get_incident_report_by_alert,
    update_alert_status,
    get_dashboard_metrics,
    create_containment_action,
    create_playbook_execution,
)
from backend.schemas import AlertDecisionRequest
from backend.engine.runner import approve_and_contain_alert, generate_and_save_report, execute_containment_workflow
from backend.config import settings
from backend.dependencies import get_current_user
from backend.integrations.tip import tip_client
from backend.integrations.nvd import nvd_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["Alerts & Cases"])

def async_enrich_alert_task(alert_id: int):
    """Background task: queries 3 TIPs in parallel and updates IoC artifacts in database."""
    db = SessionLocal()
    try:
        iocs = get_ioc_artifacts_by_alert(db, alert_id)
        max_threat = 0
        alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
        severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        highest_sev = alert.severity if alert else "Low"

        for ioc in iocs:
            res = tip_client.enrich_ioc(ioc.artifact_type, ioc.value)
            score = res.get("threat_score", 0)
            ioc.threat_score = score
            if score > max_threat:
                max_threat = score
            tip_sev = res.get("severity", "Low")
            if severity_rank.get(tip_sev, 1) > severity_rank.get(highest_sev, 1):
                highest_sev = tip_sev

        # Elevate alert severity to highest confirmed TIP threat intelligence
        if alert and severity_rank.get(highest_sev, 1) > severity_rank.get(alert.severity, 1):
            logger.info(f"Escalating Alert #{alert_id} severity to {highest_sev} based on highest TIP risk.")
            alert.severity = highest_sev

        db.commit()

        log_entry = SystemLog(
            source="TIP",
            level="ACTION" if max_threat >= 50 else "INFO",
            message=f"Multi-TIP background enrichment completed for Alert #{alert_id} across VirusTotal, AlienVault OTX, and AbuseIPDB/ThreatFox. Worst threat score: {max_threat}/100, General Severity: {alert.severity if alert else highest_sev}.",
            target=f"Alert #{alert_id}",
            details={"alert_id": alert_id, "max_threat_score": max_threat, "severity": alert.severity if alert else highest_sev, "iocs_enriched": len(iocs)}
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.error(f"Error in background TIP enrichment: {e}")
    finally:
        db.close()

@router.post("/{alert_id}/enrich-background")
def trigger_background_enrichment(
    alert_id: int, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Triggers asynchronous Multi-TIP enrichment across VirusTotal, AlienVault OTX, 
    and AbuseIPDB/ThreatFox in a non-blocking background thread.
    """
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    background_tasks.add_task(async_enrich_alert_task, alert_id)
    return {
        "status": "Queued",
        "message": f"Multi-TIP non-blocking background enrichment dispatched for Alert #{alert_id}.",
        "alert_id": alert_id
    }

@router.get("/metrics/dashboard")
def get_metrics(db: Session = Depends(get_db)):
    """Fetch aggregated real-time SOC metrics for dashboard."""
    return get_dashboard_metrics(db)

@router.delete("/purge")
def purge_all_alerts(db: Session = Depends(get_db)):
    """
    Cleans out all alerts, artifacts, executions, and actions from the system,
    leaving a pristine queue for live telemetry.
    """
    db.query(IocArtifact).delete()
    db.query(PlaybookExecution).delete()
    db.query(ContainmentAction).delete()
    db.query(IncidentReport).delete()
    db.query(AnalystActionLog).delete()
    deleted_count = db.query(Alert).delete()
    db.commit()
    return {
        "status": "success", 
        "message": f"Successfully purged {deleted_count} alerts and all associated telemetry artifacts."
    }

@router.get("")
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List and filter alerts by severity and status."""
    alerts = get_alerts(db, skip=skip, limit=limit, severity=severity, status=status)
    result = []
    for a in alerts:
        iocs = get_ioc_artifacts_by_alert(db, a.alert_id)
        max_score = max([i.threat_score for i in iocs], default=0)
        data = a.to_dict()
        data["ioc_count"] = len(iocs)
        data["max_threat_score"] = max_score
        result.append(data)
    return result

@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    """Get comprehensive alert detail including IoCs, executions, containment actions, and reports."""
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    iocs = get_ioc_artifacts_by_alert(db, alert_id)
    executions = get_executions_by_alert(db, alert_id)
    actions = get_containment_actions_by_alert(db, alert_id)
    report = get_incident_report_by_alert(db, alert_id)

    max_threat = max([i.threat_score for i in iocs], default=0)

    # MITRE ATT&CK extraction from raw_payload
    raw = alert.raw_payload or {}
    rule = raw.get("rule", {})
    mitre_data = rule.get("mitre", {
        "id": ["T1486", "T1059"] if alert.severity in ["Critical", "High"] else ["T1046" if alert.severity == "Low" else "T1566"],
        "tactic": ["Impact"] if alert.severity in ["Critical", "High"] else ["Discovery" if alert.severity == "Low" else "Initial Access"],
        "technique": ["Data Encrypted for Impact"] if alert.severity in ["Critical", "High"] else ["Network Service Discovery" if alert.severity == "Low" else "Phishing"]
    })

    # AI / SOC Executive Summary
    ai_summary = (
        f"Automated analysis of {alert.rule_id} originating from {alert.source}. "
        f"Event severity rated {alert.severity} with maximum indicator threat score of {max_threat}/100. "
        + ("Immediate HOTL autonomous containment engaged." if alert.status == "Contained"
           else ("Low-priority ticket: Analyst can choose to Take Action (Contain) or Keep for Monitoring." if alert.severity == "Low"
           else "Awaiting analyst sign-off for HITL containment actions."))
    )

    # NVD Vulnerability Context
    vulnerability_intel = nvd_client.analyze_alert_vulnerabilities(alert.to_dict())

    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "source": alert.source,
        "severity": alert.severity,
        "status": alert.status,
        "analyst_decision": alert.analyst_decision,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "raw_payload": alert.raw_payload,
        "ioc_artifacts": [i.to_dict() for i in iocs],
        "playbook_executions": [e.to_dict() for e in executions],
        "containment_actions": [a.to_dict() for a in actions],
        "incident_report": report.to_dict() if report else None,
        "mitre_attack": mitre_data,
        "ai_summary": ai_summary,
        "max_threat_score": max_threat,
        "vulnerability_intel": vulnerability_intel
    }

@router.get("/{alert_id}/vulnerabilities")
def get_alert_vulnerabilities(alert_id: int, db: Session = Depends(get_db)):
    """
    Query National Vulnerability Database (NVD) for CVEs tied to this alert.
    Returns CVSS scores, HITL remediation advice, and HOTL autonomous recommendations.
    """
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")
    return nvd_client.analyze_alert_vulnerabilities(alert.to_dict())

@router.post("/{alert_id}/vulnerabilities/execute-hotl")
def execute_cve_hotl_action(
    alert_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    HOTL (Human Out of the Loop):
    Executes programmatic automated containment based on NVD severity and fix data.
    """
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    vuln_analysis = nvd_client.analyze_alert_vulnerabilities(alert.to_dict())
    hotl_policy = vuln_analysis.get("hotl_autonomous_policy", {})
    action_type = hotl_policy.get("action_type", "isolate_endpoint")

    iocs = get_ioc_artifacts_by_alert(db, alert_id)
    mttr = execute_containment_workflow(db, alert, iocs, execution_mode="NVD HOTL Automated Remediation")
    
    alert.status = "Contained"
    cve_name = vuln_analysis['cves_detected'][0] if vuln_analysis.get('cves_detected') else 'Critical CVE'
    alert.analyst_decision = f"HOTL Automated Containment ({cve_name})"
    alert.resolved_by = "HOTL / NVD Engine"
    alert.resolved_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "status": "Success",
        "action_executed": action_type,
        "new_status": alert.status,
        "mttr_seconds": mttr,
        "nvd_policy": hotl_policy,
        "message": f"Autonomous containment action '{action_type}' successfully applied to Alert #{alert_id} based on NVD CVSS rating."
    }

@router.post("/{alert_id}/decision")
def submit_analyst_decision(
    alert_id: int, 
    req: AlertDecisionRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Action buttons for Low severity tickets (Take Action vs Keep for Monitoring):
    - 'take_action': Executes containment and changes status to 'Contained'.
    - 'keep_and_monitor': Keeps ticket benign under active monitoring without disruptive containment.
    """
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    analyst_name = req.analyst_username or current_user.username
    now = datetime.now(timezone.utc)
    iocs = get_ioc_artifacts_by_alert(db, alert_id)

    if req.decision == "take_action":
        mttr = execute_containment_workflow(db, alert, iocs, execution_mode="Analyst Discretion Containment")
        alert.status = "Contained"
        alert.analyst_decision = "Escalated & Contained by Analyst"
        alert.resolved_by = analyst_name
        alert.resolved_at = now
        db.commit()
        db.refresh(alert)

        create_playbook_execution(
            db,
            alert_id=alert.alert_id,
            status="Completed (Analyst Escalation)",
            mttr_seconds=mttr
        )
        pdf_path = generate_and_save_report(db, alert, iocs, mttr, "Low Ticket Escalated")

        # Record action log for Admin reporting
        action_log = AnalystActionLog(
            alert_id=alert.alert_id,
            analyst_username=analyst_name,
            action_type="take_action",
            decision=alert.analyst_decision,
            notes=req.notes or "Escalated low ticket to containment",
            timestamp=now
        )
        db.add(action_log)
        db.commit()

        return {
            "status": "Success",
            "decision": req.decision,
            "new_status": alert.status,
            "analyst_decision": alert.analyst_decision,
            "resolved_by": alert.resolved_by,
            "message": f"Action taken on Low ticket #{alert_id}. Host/IP containment executed.",
            "pdf_path": pdf_path
        }

    elif req.decision == "keep_and_monitor":
        alert.status = "Monitoring"
        alert.analyst_decision = "Kept as Low Risk / Continuous Monitoring"
        alert.resolved_by = analyst_name
        alert.resolved_at = now
        db.commit()
        db.refresh(alert)

        create_containment_action(db, alert.alert_id, "continuous_monitoring_policy", status="Active")

        # Record action log for Admin reporting
        action_log = AnalystActionLog(
            alert_id=alert.alert_id,
            analyst_username=analyst_name,
            action_type="keep_and_monitor",
            decision=alert.analyst_decision,
            notes=req.notes or "Maintained in continuous monitoring",
            timestamp=now
        )
        db.add(action_log)
        db.commit()

        return {
            "status": "Success",
            "decision": req.decision,
            "new_status": alert.status,
            "analyst_decision": alert.analyst_decision,
            "resolved_by": alert.resolved_by,
            "message": f"Low ticket #{alert_id} kept in monitoring mode without containment disruption."
        }

    else:
        alert.status = "Closed"
        alert.analyst_decision = "Dismissed by Analyst"
        alert.resolved_by = analyst_name
        alert.resolved_at = now
        db.commit()
        db.refresh(alert)

        action_log = AnalystActionLog(
            alert_id=alert.alert_id,
            analyst_username=analyst_name,
            action_type="dismiss",
            decision=alert.analyst_decision,
            notes=req.notes or "Dismissed ticket",
            timestamp=now
        )
        db.add(action_log)
        db.commit()

        return {
            "status": "Success",
            "decision": req.decision,
            "new_status": alert.status,
            "analyst_decision": alert.analyst_decision,
            "resolved_by": alert.resolved_by,
            "message": f"Ticket #{alert_id} closed."
        }

@router.post("/{alert_id}/approve")
def approve_alert(
    alert_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manual analyst sign-off for HITL alerts."""
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    now = datetime.now(timezone.utc)
    try:
        result = approve_and_contain_alert(db, alert_id)
        alert.resolved_by = current_user.username
        alert.resolved_at = now
        alert.analyst_decision = "Approved & Contained (HITL)"
        
        action_log = AnalystActionLog(
            alert_id=alert.alert_id,
            analyst_username=current_user.username,
            action_type="approve",
            decision=alert.analyst_decision,
            notes="Analyst granted HITL containment sign-off",
            timestamp=now
        )
        db.add(action_log)
        db.commit()

        return {
            "status": "Success",
            "message": f"Alert #{alert_id} approved. Containment actions executed.",
            "data": result,
            "resolved_by": current_user.username
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing containment: {str(e)}")

@router.post("/{alert_id}/dismiss")
def dismiss_alert(
    alert_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Dismiss or deny an alert as false positive or acceptable risk."""
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    now = datetime.now(timezone.utc)
    alert.status = "Closed"
    alert.analyst_decision = "Dismissed as False Positive"
    alert.resolved_by = current_user.username
    alert.resolved_at = now
    db.commit()
    db.refresh(alert)

    action_log = AnalystActionLog(
        alert_id=alert.alert_id,
        analyst_username=current_user.username,
        action_type="dismiss",
        decision=alert.analyst_decision,
        notes="Dismissed as False Positive",
        timestamp=now
    )
    db.add(action_log)
    db.commit()

    return {
        "status": "Success",
        "message": f"Alert #{alert_id} dismissed and closed by analyst.",
        "alert_id": alert_id,
        "current_status": alert.status,
        "resolved_by": current_user.username
    }

@router.get("/{alert_id}/report")
def stream_pdf_report(alert_id: int, db: Session = Depends(get_db)):
    """Streams the ReportLab executive PDF report."""
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    report = get_incident_report_by_alert(db, alert_id)
    pdf_path = None

    if report and os.path.exists(report.pdf_path):
        pdf_path = report.pdf_path
    else:
        iocs = get_ioc_artifacts_by_alert(db, alert_id)
        executions = get_executions_by_alert(db, alert_id)
        mttr = executions[0].mttr_seconds if executions else 1.85
        mode = "HOTL" if alert.severity in ["Critical", "High"] else "HITL"
        pdf_path = generate_and_save_report(db, alert, iocs, mttr, mode)

    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Failed to locate generated PDF report")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"phantom_soar_incident_report_{alert_id}.pdf"
    )
