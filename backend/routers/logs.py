import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.database import get_db
from backend.models import SystemLog, Alert, ContainmentAction

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Telemetry & Audit Logs"])

class LogCreateRequest(BaseModel):
    source: str  # EDR, XDR, SIEM, TIP, FIREWALL, IAM, ITSM, AUTOMATION
    level: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL, ACTION
    message: str
    target: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

def get_naive_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def record_log(
    db: Session, 
    source: str, 
    level: str, 
    message: str, 
    target: Optional[str] = None, 
    details: Optional[Dict[str, Any]] = None,
    created_at: Optional[datetime] = None
) -> SystemLog:
    """Helper to persist a system or telemetry log event."""
    log_entry = SystemLog(
        source=source.upper(),
        level=level.upper(),
        message=message,
        target=target,
        details=details or {},
        created_at=created_at or get_naive_utc()
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def ensure_seed_logs(db: Session):
    """Seed or refresh initial multi-source security events across different time intervals."""
    now = get_naive_utc()
    latest = db.query(SystemLog).order_by(SystemLog.created_at.desc()).first()

    # If empty or latest event is older than 25 seconds, refresh real-time logs
    if latest and (now - latest.created_at).total_seconds() <= 25:
        return

    now = datetime.now(timezone.utc)
    sample_events = [
        # Very recent (within last 30 seconds)
        {
            "source": "EDR",
            "level": "CRITICAL",
            "message": "CrowdStrike Falcon detected suspicious process injection (vssadmin.exe delete shadows)",
            "target": "WIN-SRV-01 (10.0.4.15)",
            "details": {"pid": 4812, "parent_pid": 1024, "technique": "T1490", "action": "Process suspended"},
            "delta_seconds": 8
        },
        {
            "source": "SIEM",
            "level": "ACTION",
            "message": "Wazuh Rule 99901 triggered: Cobalt Strike C2 DNS beaconing detected",
            "target": "185.220.101.5",
            "details": {"rule_id": "99901", "level": 13, "agent_id": "004", "protocol": "DNS/UDP"},
            "delta_seconds": 18
        },
        {
            "source": "XDR",
            "level": "WARNING",
            "message": "Cortex XDR identity anomaly: Multiple failed Kerberos ticket requests (AS-REP Roasting)",
            "target": "corp\\jdoe (10.0.2.88)",
            "details": {"ticket_type": "RC4-HMAC", "attempts": 14, "risk_score": 82},
            "delta_seconds": 25
        },

        # Within last 60 seconds
        {
            "source": "FIREWALL",
            "level": "ACTION",
            "message": "Palo Alto Panorama deployed dynamic drop rule for malicious outbound C2 IP",
            "target": "185.220.101.5:443",
            "details": {"action": "DROP", "zone": "UNTRUST", "rule_name": "AUTO_SOAR_EDGE_BLOCK"},
            "delta_seconds": 45
        },
        {
            "source": "TIP",
            "level": "INFO",
            "message": "VirusTotal intelligence query completed: Hash malicious ratio 68/72",
            "target": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "details": {"threat_score": 94, "reputation": "Malware/Ransomware.LockBit"},
            "delta_seconds": 55
        },

        # Within last 300 seconds (5 minutes)
        {
            "source": "EDR",
            "level": "ACTION",
            "message": "Endpoint isolation command successfully executed: Host WIN-SRV-01 network severed",
            "target": "WIN-SRV-01",
            "details": {"management_tunnel": "retained", "subnets_blocked": ["0.0.0.0/0"]},
            "delta_seconds": 110
        },
        {
            "source": "IAM",
            "level": "ACTION",
            "message": "Active Directory account locked and OAuth2 refresh tokens revoked",
            "target": "admin_backup",
            "details": {"revoked_sessions": 3, "directory": "Azure AD / Okta"},
            "delta_seconds": 180
        },
        {
            "source": "SIEM",
            "level": "WARNING",
            "message": "Wazuh Agent 007 reported abnormal PowerShell execution with base64 encoded payload",
            "target": "WORKSTATION-09 (10.0.2.14)",
            "details": {"rule_id": "99903", "encoded_command": "powershell -enc JABzACAAPQ..."},
            "delta_seconds": 240
        },

        # Within last 900 seconds (15 minutes)
        {
            "source": "ITSM",
            "level": "INFO",
            "message": "Jira Service Management ticket #SEC-1042 opened and routed to Tier 2 Incident Responder",
            "target": "SEC-1042",
            "details": {"priority": "High", "assignee": "abunemah", "sla_minutes": 15},
            "delta_seconds": 450
        },
        {
            "source": "AUTOMATION",
            "level": "ACTION",
            "message": "Playbook 'Ransomware Outbreak Containment' executed in HOTL Autonomous mode",
            "target": "Alert #101",
            "details": {"mttr_seconds": 1.4, "steps_completed": 5, "pdf_report": "generated"},
            "delta_seconds": 600
        },
        {
            "source": "XDR",
            "level": "INFO",
            "message": "Cloud trail anomaly: AWS AssumeRole from unrecognized external IP",
            "target": "arn:aws:iam::123456789012:role/SecOpsAdmin",
            "details": {"source_ip": "194.26.29.112", "region": "us-east-1"},
            "delta_seconds": 800
        },

        # Older (within last hour)
        {
            "source": "TIP",
            "level": "INFO",
            "message": "AbuseIPDB reputation lookup: IP confidence score 100% (High risk scanner)",
            "target": "194.26.29.112",
            "details": {"total_reports": 412, "country": "RU"},
            "delta_seconds": 1800
        },
        {
            "source": "FIREWALL",
            "level": "WARNING",
            "message": "Perimeter rate limit threshold exceeded on SSH port 22 (120 syn/sec)",
            "target": "203.0.113.8",
            "details": {"action": "RateLimited", "burst": 50},
            "delta_seconds": 2400
        },
        {
            "source": "AUTH",
            "level": "INFO",
            "message": "Operator 'abunemah' authenticated to SOC Console via Web API session",
            "target": "127.0.0.1",
            "details": {"role": "Lead SOC Architect / Admin", "session": "active"},
            "delta_seconds": 3200
        }
    ]

    for ev in sample_events:
        event_time = now - timedelta(seconds=ev["delta_seconds"])
        log_item = SystemLog(
            source=ev["source"],
            level=ev["level"],
            message=ev["message"],
            target=ev["target"],
            details=ev["details"],
            created_at=event_time
        )
        db.add(log_item)
    db.commit()

@router.get("")
def list_logs(
    source: Optional[str] = Query(None, description="Filter by source: EDR, XDR, SIEM, TIP, FIREWALL, IAM, ITSM, AUTOMATION"),
    seconds: Optional[int] = Query(None, ge=1, description="Filter logs generated within the last N seconds (e.g. 30, 60, 300, 3600)"),
    level: Optional[str] = Query(None, description="Filter by level: INFO, WARNING, ERROR, CRITICAL, ACTION"),
    search: Optional[str] = Query(None, description="Search across messages, targets, and details"),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """
    Retrieve unified SOC security logs and telemetry.
    Supports filtering by source connector (EDR, XDR, SIEM, etc.) and time in seconds.
    """
    query = db.query(SystemLog)

    # 1. Source Filter (EDR, XDR, SIEM, TIP, FIREWALL, IAM, ITSM, AUTOMATION)
    if source and source.strip() and source.upper() != "ALL":
        query = query.filter(SystemLog.source == source.strip().upper())

    # 2. Time Filter in seconds (within last N seconds)
    if seconds is not None and seconds > 0:
        cutoff = get_naive_utc() - timedelta(seconds=seconds)
        query = query.filter(SystemLog.created_at >= cutoff)

    # 3. Level Filter
    if level and level.strip() and level.upper() != "ALL":
        query = query.filter(SystemLog.level == level.strip().upper())

    # 4. Keyword Search
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SystemLog.message.ilike(term),
                SystemLog.target.ilike(term),
                SystemLog.source.ilike(term)
            )
        )

    # Sort descending by timestamp
    logs = query.order_by(SystemLog.created_at.desc()).limit(limit).all()

    return [l.to_dict() for l in logs]

@router.post("", status_code=status.HTTP_201_CREATED)
def create_log(payload: LogCreateRequest, db: Session = Depends(get_db)):
    """Append a new real-time log event to the telemetry engine."""
    entry = record_log(
        db=db,
        source=payload.source,
        level=payload.level,
        message=payload.message,
        target=payload.target,
        details=payload.details
    )
    return entry.to_dict()

@router.post("/seed")
def seed_fresh_logs(db: Session = Depends(get_db)):
    """Inject fresh live telemetry logs relative to current timestamp."""
    now = datetime.now(timezone.utc)
    fresh_entries = [
        {
            "source": "SIEM",
            "level": "CRITICAL",
            "message": "Wazuh Agent alert: Suspicious execution of Mimikatz memory dump tool",
            "target": "WIN-DC-01 (10.0.1.5)",
            "details": {"rule_id": "99915", "process": "lsass.exe", "tactic": "Credential Access"},
            "delta_seconds": 2
        },
        {
            "source": "EDR",
            "level": "ACTION",
            "message": "CrowdStrike active quarantine: Blocked malicious memory read on lsass.exe",
            "target": "WIN-DC-01",
            "details": {"action": "Blocked", "sha256": "8a72b..."},
            "delta_seconds": 5
        },
        {
            "source": "XDR",
            "level": "WARNING",
            "message": "Cortex XDR correlated lateral movement attempt to Domain Controller",
            "target": "10.0.1.5 -> 10.0.4.12",
            "details": {"technique": "T1021.002", "confidence": 92},
            "delta_seconds": 12
        },
        {
            "source": "FIREWALL",
            "level": "ACTION",
            "message": "Firewall ACL enforced: Internal subnet isolation for compromised endpoint",
            "target": "10.0.4.12",
            "details": {"vlan": 40, "status": "ISOLATED"},
            "delta_seconds": 20
        }
    ]

    for ev in fresh_entries:
        db.add(SystemLog(
            source=ev["source"],
            level=ev["level"],
            message=ev["message"],
            target=ev["target"],
            details=ev["details"],
            created_at=now - timedelta(seconds=ev["delta_seconds"])
        ))
    db.commit()

    return {"status": "Success", "message": "Injected fresh live telemetry logs."}

@router.delete("")
def clear_logs(db: Session = Depends(get_db)):
    """Purge all logs."""
    db.query(SystemLog).delete()
    db.commit()
    return {"status": "Success", "message": "All telemetry logs cleared."}
