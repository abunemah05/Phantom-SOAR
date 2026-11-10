import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Alert, IocArtifact, Playbook, PlaybookExecution, ContainmentAction, IncidentReport
from backend.crud import (
    create_alert,
    create_ioc_artifact,
    create_containment_action,
    create_playbook_execution,
    create_playbook,
    create_incident_report
)
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS
from backend.engine.reporter import generate_pdf_report

router = APIRouter(prefix="/demo", tags=["Demo Seeder"])

@router.post("/seed", status_code=status.HTTP_201_CREATED)
def seed_demo_data(db: Session = Depends(get_db)):
    """
    Seeds pre-configured test cases for university graduation defense and live presentations:
    1. Populates 12 SANS / MITRE IR Playbooks.
    2. Critical Ransomware Alert (autonomous HOTL containment, MTTR 1.42s, Report generated).
    3. Medium Phishing Alert (HITL Triaged, awaiting analyst approval button).
    4. High WebShell Backdoor (autonomous HOTL containment).
    5. Low Reconnaissance / Probe (New).
    """
    # 1. Seed 12 Playbooks
    existing_playbooks = {p.name: p for p in db.query(Playbook).all()}
    seeded_playbooks = []
    for pb in PRECONFIGURED_PLAYBOOKS:
        if pb["name"] not in existing_playbooks:
            created_pb = create_playbook(db, pb)
            seeded_playbooks.append(created_pb)
        else:
            seeded_playbooks.append(existing_playbooks[pb["name"]])

    # 2. Seed Case A: Critical Ransomware (HOTL Contained)
    raw_ransomware = {
        "rule": {
            "id": "100201",
            "level": 14,
            "description": "Critical Ransomware Activity: Bulk Encryption & Volume Shadow Copy Deletion",
            "mitre": {
                "id": ["T1486", "T1490"],
                "tactic": ["Impact"],
                "technique": ["Data Encrypted for Impact", "Inhibit System Recovery"]
            }
        },
        "agent": {"id": "004", "name": "srv-prod-db01", "ip": "10.0.4.15"},
        "data": {
            "process": "lockbit3_encryptor.exe",
            "command": "vssadmin.exe delete shadows /all /quiet",
            "srcip": "198.51.100.45",
            "srcuser": "svc_sqladmin",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f"
        },
        "full_log": "Ransomware signature match. Attempted bulk rename to .lockbit extension on C:\\Shares\\Data"
    }

    alert_ransomware = create_alert(db, {
        "rule_id": "WAZUH-RANSOM-100201",
        "source": "Wazuh SIEM",
        "severity": "Critical",
        "status": "Contained",
        "raw_payload": raw_ransomware,
        "created_at": datetime.utcnow() - timedelta(minutes=45)
    })

    ioc_rw1 = create_ioc_artifact(db, alert_ransomware.alert_id, "Hash", "44d88612fea8a8f36de82e1278abb02f", 95)
    ioc_rw2 = create_ioc_artifact(db, alert_ransomware.alert_id, "IP", "198.51.100.45", 92)
    ioc_rw3 = create_ioc_artifact(db, alert_ransomware.alert_id, "Domain", "lockbit-c2-beacon.darknet", 88)

    create_containment_action(db, alert_ransomware.alert_id, "isolate_endpoint (srv-prod-db01)", "Executed")
    create_containment_action(db, alert_ransomware.alert_id, "terminate_process (lockbit3_encryptor.exe)", "Executed")
    create_containment_action(db, alert_ransomware.alert_id, "block_ip (198.51.100.45)", "Executed")
    create_containment_action(db, alert_ransomware.alert_id, "terminate_session (svc_sqladmin)", "Executed")

    pb_rw = next((p for p in seeded_playbooks if "Ransomware" in p.name), None)
    create_playbook_execution(
        db,
        alert_id=alert_ransomware.alert_id,
        playbook_id=pb_rw.playbook_id if pb_rw else None,
        status="Completed",
        mttr_seconds=1.42
    )

    pdf_path_rw = generate_pdf_report({
        "alert_id": alert_ransomware.alert_id,
        "rule_id": alert_ransomware.rule_id,
        "source": alert_ransomware.source,
        "severity": alert_ransomware.severity,
        "status": alert_ransomware.status,
        "created_at": alert_ransomware.created_at.isoformat(),
        "mttr_seconds": 1.42,
        "execution_mode": "HOTL (Autonomous Containment)",
        "threat_name": "LockBit 3.0 Ransomware Attack",
        "ioc_artifacts": [
            {"artifact_type": ioc_rw1.artifact_type, "value": ioc_rw1.value, "threat_score": ioc_rw1.threat_score},
            {"artifact_type": ioc_rw2.artifact_type, "value": ioc_rw2.value, "threat_score": ioc_rw2.threat_score},
            {"artifact_type": ioc_rw3.artifact_type, "value": ioc_rw3.value, "threat_score": ioc_rw3.threat_score},
        ],
        "containment_actions": [
            {"action_type": "isolate_endpoint (srv-prod-db01)", "status": "Executed"},
            {"action_type": "terminate_process (lockbit3_encryptor.exe)", "status": "Executed"},
            {"action_type": "block_ip (198.51.100.45)", "status": "Executed"},
            {"action_type": "terminate_session (svc_sqladmin)", "status": "Executed"},
        ]
    })
    create_incident_report(db, alert_ransomware.alert_id, pdf_path_rw)

    # 3. Seed Case B: Medium Phishing (HITL Triaged - Awaiting Analyst Approval)
    raw_phishing = {
        "rule": {
            "id": "100340",
            "level": 6,
            "description": "Suspicious Inbound Email with Credential Harvesting Link",
            "mitre": {
                "id": ["T1566.002"],
                "tactic": ["Initial Access"],
                "technique": ["Spearphishing Link"]
            }
        },
        "agent": {"id": "002", "name": "mail-relay-edge", "ip": "10.0.1.20"},
        "data": {
            "sender": "payroll-alert@update-banking-services.net",
            "recipient": "hr_manager@university.edu",
            "url": "http://evil-phishing-login.secure-bank.xyz/verify",
            "srcip": "45.33.32.156"
        },
        "full_log": "SPF softfail: sender IP 45.33.32.156 not aligned with envelope domain. Target URL contains banking impersonation."
    }

    alert_phishing = create_alert(db, {
        "rule_id": "WAZUH-PHISH-100340",
        "source": "Wazuh SIEM",
        "severity": "Medium",
        "status": "Triaged",
        "raw_payload": raw_phishing,
        "created_at": datetime.utcnow() - timedelta(minutes=15)
    })

    create_ioc_artifact(db, alert_phishing.alert_id, "URL", "http://evil-phishing-login.secure-bank.xyz/verify", 48)
    create_ioc_artifact(db, alert_phishing.alert_id, "IP", "45.33.32.156", 45)

    pb_phish = next((p for p in seeded_playbooks if "Phishing" in p.name), None)
    create_playbook_execution(
        db,
        alert_id=alert_phishing.alert_id,
        playbook_id=pb_phish.playbook_id if pb_phish else None,
        status="Pending Analyst Approval",
        mttr_seconds=0.0
    )

    # 4. Seed Case C: High WebShell Execution (HOTL Contained)
    raw_webshell = {
        "rule": {
            "id": "100412",
            "level": 11,
            "description": "Web Shell Execution Detected on Nginx Public Gateway",
            "mitre": {
                "id": ["T1505.003"],
                "tactic": ["Persistence"],
                "technique": ["Web Shell"]
            }
        },
        "agent": {"id": "001", "name": "web-prod-nginx01", "ip": "10.0.2.8"},
        "data": {
            "process": "/usr/bin/python3 -c import socket,subprocess...",
            "srcip": "185.220.101.5",
            "srcuser": "www-data",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "full_log": "Reverse bash shell spawned by web server child process under /var/www/html/uploads/shell.php"
    }

    alert_webshell = create_alert(db, {
        "rule_id": "WAZUH-WEBSHELL-100412",
        "source": "Wazuh SIEM",
        "severity": "High",
        "status": "Contained",
        "raw_payload": raw_webshell,
        "created_at": datetime.utcnow() - timedelta(minutes=120)
    })

    create_ioc_artifact(db, alert_webshell.alert_id, "IP", "185.220.101.5", 88)
    create_ioc_artifact(db, alert_webshell.alert_id, "Hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 85)

    create_containment_action(db, alert_webshell.alert_id, "isolate_endpoint (web-prod-nginx01)", "Executed")
    create_containment_action(db, alert_webshell.alert_id, "block_ip (185.220.101.5)", "Executed")

    pb_web = next((p for p in seeded_playbooks if "Web Shell" in p.name), None)
    create_playbook_execution(
        db,
        alert_id=alert_webshell.alert_id,
        playbook_id=pb_web.playbook_id if pb_web else None,
        status="Completed",
        mttr_seconds=1.68
    )

    pdf_path_web = generate_pdf_report({
        "alert_id": alert_webshell.alert_id,
        "rule_id": alert_webshell.rule_id,
        "source": alert_webshell.source,
        "severity": alert_webshell.severity,
        "status": alert_webshell.status,
        "created_at": alert_webshell.created_at.isoformat(),
        "mttr_seconds": 1.68,
        "execution_mode": "HOTL (Autonomous Containment)",
        "threat_name": "Web Shell Backdoor Incident",
        "ioc_artifacts": [
            {"artifact_type": "IP", "value": "185.220.101.5", "threat_score": 88},
            {"artifact_type": "Hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "threat_score": 85}
        ],
        "containment_actions": [
            {"action_type": "isolate_endpoint (web-prod-nginx01)", "status": "Executed"},
            {"action_type": "block_ip (185.220.101.5)", "status": "Executed"}
        ]
    })
    create_incident_report(db, alert_webshell.alert_id, pdf_path_web)

    # 5. Seed Case D: Low Port Reconnaissance (New)
    alert_scan = create_alert(db, {
        "rule_id": "WAZUH-RECON-5701",
        "source": "Wazuh SIEM",
        "severity": "Low",
        "status": "New",
        "raw_payload": {
            "rule": {"id": "5701", "level": 3, "description": "TCP Port Scan Detected on DMZ Gateway"},
            "agent": {"id": "003", "name": "dmz-fw01"},
            "data": {"srcip": "192.168.1.105"}
        },
        "created_at": datetime.utcnow() - timedelta(minutes=5)
    })
    create_ioc_artifact(db, alert_scan.alert_id, "IP", "192.168.1.105", 15)

    return {
        "status": "Success",
        "message": "Demo data successfully seeded with 12 playbooks, Critical Ransomware (HOTL), Medium Phishing (HITL), High WebShell, and Low Recon alerts.",
        "seeded_playbooks_count": len(seeded_playbooks),
        "seeded_alerts": [
            {"alert_id": alert_ransomware.alert_id, "type": "Ransomware (HOTL Contained)"},
            {"alert_id": alert_phishing.alert_id, "type": "Phishing (HITL Triaged)"},
            {"alert_id": alert_webshell.alert_id, "type": "WebShell (HOTL Contained)"},
            {"alert_id": alert_scan.alert_id, "type": "Recon (New)"}
        ]
    }
