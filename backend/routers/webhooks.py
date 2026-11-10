import logging
import os
import re
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Alert
from backend.crud import create_alert, create_ioc_artifact
from backend.integrations.tip import tip_client
from backend.celery_app import process_alert_task
from backend.engine.runner import process_alert
from backend.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks & Ingestion"])

def is_celery_broker_online() -> bool:
    """Quick 100ms socket probe to test if Redis broker is actively listening."""
    try:
        parsed = urlparse(settings.CELERY_BROKER_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        with socket.create_connection((host, port), timeout=0.15):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def map_wazuh_level_to_severity(level: int) -> str:
    """Map Wazuh rule level (0-16) to standard SOAR severity."""
    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 5:
        return "Medium"
    return "Low"

def extract_iocs_from_payload(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    """Scan Wazuh payload and log strings for IP, Hash, Domain, and URL indicators."""
    iocs = []
    seen = set()

    data = payload.get("data", {})
    full_log = payload.get("full_log", "")

    # 1. IP extraction
    for ip_key in ["srcip", "dstip", "src_ip", "dst_ip", "client_ip", "attacker_ip"]:
        if ip_key in data and data[ip_key]:
            ip_val = str(data[ip_key]).strip()
            if ip_val and ip_val not in seen:
                seen.add(ip_val)
                iocs.append({"artifact_type": "IP", "value": ip_val})

    # Regex search for IPv4 in full_log if no IP found in data
    if not any(i["artifact_type"] == "IP" for i in iocs) and full_log:
        ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", full_log)
        for ip in ip_matches:
            if ip not in ["127.0.0.1", "0.0.0.0"] and ip not in seen:
                seen.add(ip)
                iocs.append({"artifact_type": "IP", "value": ip})
                break

    # 2. Hash extraction (MD5 / SHA256)
    for hash_key in ["md5", "sha256", "file_hash", "hash"]:
        if hash_key in data and data[hash_key]:
            h_val = str(data[hash_key]).strip()
            if h_val and h_val not in seen:
                seen.add(h_val)
                iocs.append({"artifact_type": "Hash", "value": h_val})

    # Regex search for MD5 or SHA256
    if full_log:
        sha256_matches = re.findall(r"\b[a-fA-F0-9]{64}\b", full_log)
        for h in sha256_matches:
            if h not in seen:
                seen.add(h)
                iocs.append({"artifact_type": "Hash", "value": h})

    # 3. URL / Domain extraction
    for url_key in ["url", "domain", "uri", "target_url"]:
        if url_key in data and data[url_key]:
            u_val = str(data[url_key]).strip()
            if u_val and u_val not in seen:
                seen.add(u_val)
                iocs.append({"artifact_type": "URL" if "http" in u_val else "Domain", "value": u_val})

    return iocs

@router.post("/wazuh", status_code=status.HTTP_201_CREATED)
async def ingest_wazuh_alert(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Ingests Wazuh SIEM JSON alert telemetry.
    Parses rule ID, calculates severity, extracts IoCs, performs TIP enrichment,
    and dispatches Celery background task for automated triage.
    """
    rule = payload.get("rule", {})
    rule_id = str(rule.get("id", payload.get("id", "WAZUH-ALERT-1001")))
    rule_level = rule.get("level", 8)
    severity = map_wazuh_level_to_severity(rule_level)

    # Allow explicit severity override in payload if present
    if "severity" in payload:
        severity = payload["severity"].capitalize()

    # Create alert record
    alert_record = create_alert(db, {
        "rule_id": rule_id,
        "source": "Wazuh SIEM",
        "severity": severity,
        "status": "New",
        "raw_payload": payload
    })

    # Extract and enrich IoCs
    extracted_iocs = extract_iocs_from_payload(payload)
    created_artifacts = []
    max_threat = 0
    highest_tip_severity = alert_record.severity
    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    for ioc in extracted_iocs:
        tip_result = tip_client.enrich_ioc(ioc["artifact_type"], ioc["value"])
        threat_score = tip_result["threat_score"]
        if threat_score > max_threat:
            max_threat = threat_score

        tip_sev = tip_result.get("severity", "Low")
        if severity_rank.get(tip_sev, 1) > severity_rank.get(highest_tip_severity, 1):
            highest_tip_severity = tip_sev

        artifact = create_ioc_artifact(
            db=db,
            alert_id=alert_record.alert_id,
            artifact_type=ioc["artifact_type"],
            value=ioc["value"],
            threat_score=threat_score
        )
        created_artifacts.append(artifact.to_dict())

    # Escalate alert severity if any TIP flagged higher risk than original telemetry
    if severity_rank.get(highest_tip_severity, 1) > severity_rank.get(alert_record.severity, 1):
        logger.info(f"Escalating Alert #{alert_record.alert_id} severity to {highest_tip_severity} based on worst TIP threat intelligence.")
        alert_record.severity = highest_tip_severity
        db.commit()
        db.refresh(alert_record)

    # Dispatch Celery background task if broker is live, otherwise execute runner synchronously
    celery_dispatched = False
    if is_celery_broker_online():
        try:
            process_alert_task.apply_async(args=[alert_record.alert_id], retry=False)
            celery_dispatched = True
            logger.info(f"Dispatched Celery task for Alert #{alert_record.alert_id}")
        except Exception as e:
            logger.warning(f"Error enqueueing Celery task ({e}). Falling back to sync runner.")
            process_alert(alert_record.alert_id)
    else:
        logger.info(f"Broker offline or in standalone mode. Executing runner synchronously for Alert #{alert_record.alert_id}")
        process_alert(alert_record.alert_id)

    # Also record in unified telemetry logs
    from backend.routers.logs import record_log
    record_log(
        db=db,
        source="SIEM",
        level="ACTION" if severity in ["Critical", "High"] else "WARNING",
        message=f"Wazuh SIEM alert received: {rule.get('description', rule_id)}",
        target=payload.get("agent", {}).get("name", rule_id),
        details=payload
    )

    db.refresh(alert_record)

    return {
        "status": "Success",
        "message": f"Wazuh alert {rule_id} ingested successfully.",
        "alert_id": alert_record.alert_id,
        "severity": alert_record.severity,
        "current_status": alert_record.status,
        "celery_background_dispatched": celery_dispatched,
        "ioc_count": len(created_artifacts),
        "iocs": created_artifacts
    }


@router.post("/edr", status_code=status.HTTP_201_CREATED)
async def ingest_edr_alert(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Ingest telemetry directly from EDR agents (OpenEDR, CrowdStrike, Wazuh Active Response, Sysmon).
    Captures process execution trees, memory injection, kernel hooks, and quarantine events.
    """
    from backend.routers.logs import record_log

    rule_id = str(payload.get("rule_id", payload.get("alert_id", "EDR-BEHAVIOR-801")))
    severity = str(payload.get("severity", "Critical")).capitalize()
    process_info = payload.get("process", {})
    agent_info = payload.get("agent", {})
    hostname = agent_info.get("hostname", payload.get("hostname", "WIN-ENDPOINT-01"))
    process_name = process_info.get("name", payload.get("process_name", "suspicious_process.exe"))

    alert_record = create_alert(db, {
        "rule_id": rule_id,
        "source": "EDR (Endpoint Agent)",
        "severity": severity,
        "status": "New",
        "raw_payload": payload
    })

    # Extract IoCs
    extracted_iocs = extract_iocs_from_payload(payload)
    if "hash" in payload and payload["hash"]:
        extracted_iocs.append({"artifact_type": "Hash", "value": str(payload["hash"]).strip()})
    if "ip" in agent_info and agent_info["ip"]:
        extracted_iocs.append({"artifact_type": "IP", "value": str(agent_info["ip"]).strip()})

    created_artifacts = []
    for ioc in extracted_iocs:
        tip_result = tip_client.enrich_ioc(ioc["artifact_type"], ioc["value"])
        artifact = create_ioc_artifact(
            db=db,
            alert_id=alert_record.alert_id,
            artifact_type=ioc["artifact_type"],
            value=ioc["value"],
            threat_score=tip_result["threat_score"]
        )
        created_artifacts.append(artifact.to_dict())

    # Log in Telemetry stream
    record_log(
        db=db,
        source="EDR",
        level="CRITICAL" if severity == "Critical" else "ACTION",
        message=f"EDR detected suspicious process: {process_name} on host {hostname}",
        target=f"{hostname} (PID {process_info.get('pid', 'unknown')})",
        details=payload
    )

    # Execute triage pipeline
    process_alert(alert_record.alert_id)
    db.refresh(alert_record)

    return {
        "status": "Success",
        "message": f"EDR alert {rule_id} processed successfully.",
        "alert_id": alert_record.alert_id,
        "severity": alert_record.severity,
        "current_status": alert_record.status,
        "target_host": hostname,
        "target_process": process_name,
        "iocs": created_artifacts
    }


@router.post("/xdr", status_code=status.HTTP_201_CREATED)
async def ingest_xdr_incident(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Ingest cross-layer incident stories from XDR engines (Cortex XDR, multi-silo correlation).
    Correlates across Endpoint, Network perimeter, and Cloud/Identity layers.
    """
    from backend.routers.logs import record_log

    incident_id = str(payload.get("incident_id", payload.get("id", "XDR-CORR-9042")))
    severity = str(payload.get("severity", "High")).capitalize()
    mitre_tactic = payload.get("mitre_tactic", "Lateral Movement / Multi-Layer Attack")
    layers = payload.get("correlated_layers", ["Endpoint", "Network", "Identity"])

    alert_record = create_alert(db, {
        "rule_id": incident_id,
        "source": "XDR (Cross-Layer Correlation)",
        "severity": severity,
        "status": "New",
        "raw_payload": payload
    })

    # Extract IoCs
    extracted_iocs = extract_iocs_from_payload(payload)
    created_artifacts = []
    for ioc in extracted_iocs:
        tip_result = tip_client.enrich_ioc(ioc["artifact_type"], ioc["value"])
        artifact = create_ioc_artifact(
            db=db,
            alert_id=alert_record.alert_id,
            artifact_type=ioc["artifact_type"],
            value=ioc["value"],
            threat_score=tip_result["threat_score"]
        )
        created_artifacts.append(artifact.to_dict())

    # Log in Telemetry stream
    record_log(
        db=db,
        source="XDR",
        level="CRITICAL" if severity == "Critical" else "WARNING",
        message=f"XDR multi-layer correlation incident: {mitre_tactic} across {', '.join(layers)}",
        target=str(payload.get("target", payload.get("hosts", ["10.0.4.15"]))),
        details=payload
    )

    # Execute triage pipeline
    process_alert(alert_record.alert_id)
    db.refresh(alert_record)

    return {
        "status": "Success",
        "message": f"XDR incident {incident_id} processed successfully.",
        "alert_id": alert_record.alert_id,
        "severity": alert_record.severity,
        "current_status": alert_record.status,
        "correlated_layers": layers,
        "iocs": created_artifacts
    }
