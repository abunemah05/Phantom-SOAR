"""Lab demo seeder.

Sends lab payloads through the real ingestion pipeline (ingest_alert -> TIP -> runner), so
every score, verdict, containment action and MTTR shown afterwards was produced by the
platform itself. Only available in simulation mode: the IOCs are explicit lab fixtures
(documentation-range IPs, EICAR test-file hashes, ".example" domains) and unconfigured
connectors record clearly-labelled simulated actions.
"""
import copy
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.crud import create_playbook
from backend.database import get_db
from backend.dependencies import require_admin
from backend.engine.ingest import ingest_alert_with_details
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS
from backend.integration_config import is_simulation_mode
from backend.models import Playbook, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/demo", tags=["Demo Seeder"])

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

LAB_SCENARIOS: List[Dict[str, Any]] = [
    {
        "scenario": "ransomware",
        "type": "Ransomware (Critical, lab-fixture malicious IOCs)",
        "expected": "Critical telemetry and Malicious IOC evidence; the HOTL ransomware playbook may contain it autonomously.",
        "payload": {
            "rule": {
                "id": "100201",
                "level": 14,
                "description": "Ransomware activity: bulk file encryption and Volume Shadow Copy deletion",
                "mitre": {
                    "id": ["T1486", "T1490"],
                    "tactic": ["Impact"],
                    "technique": ["Data Encrypted for Impact", "Inhibit System Recovery"],
                },
            },
            "agent": {"id": "004", "name": "srv-prod-db01", "ip": "10.0.4.15"},
            "data": {
                "process": "lockbit3_encryptor.exe",
                "command": "vssadmin.exe delete shadows /all /quiet",
                "srcip": "198.51.100.45",
                "srcuser": "svc_sqladmin",
                "file_hash": EICAR_MD5,
            },
            "full_log": (
                "Bulk rename of files to the .lockbit extension under C:\\Shares\\Data; "
                "process beaconing to c2-beacon.lab.example. Sample hash matches the EICAR test file "
                "(lab stand-in for the encryptor)."
            ),
        },
    },
    {
        "scenario": "phishing",
        "type": "Phishing (Medium, waits for analyst approval)",
        "expected": "Suspicious IOC evidence and a HITL playbook, so it waits for an analyst decision.",
        "payload": {
            "rule": {
                "id": "100340",
                "level": 6,
                "description": "Phishing: inbound email with a credential-harvesting link",
                "mitre": {
                    "id": ["T1566.002"],
                    "tactic": ["Initial Access"],
                    "technique": ["Spearphishing Link"],
                },
            },
            "agent": {"id": "002", "name": "mail-relay-edge", "ip": "10.0.1.20"},
            "data": {
                "sender": "payroll-alert@update-banking-services.example",
                "recipient": "hr_manager@university.example",
                "url": "http://login-verify.phish.example/verify",
                "srcip": "192.0.2.77",
                "dstuser": "hr_manager",
            },
            "full_log": "SPF softfail: sender IP 192.0.2.77 not aligned with the envelope domain; link impersonates a banking login page.",
        },
    },
    {
        "scenario": "webshell",
        "type": "WebShell (High, lab-fixture malicious IOCs)",
        "expected": "High telemetry and Malicious IOC evidence; the HOTL web-shell playbook may contain it autonomously.",
        "payload": {
            "rule": {
                "id": "100412",
                "level": 11,
                "description": "WebShell execution detected on the public Nginx gateway",
                "mitre": {"id": ["T1505.003"], "tactic": ["Persistence"], "technique": ["Web Shell"]},
            },
            "agent": {"id": "001", "name": "web-prod-nginx01", "ip": "10.0.2.8"},
            "data": {
                "process": "/usr/bin/python3 -c import socket,subprocess",
                "srcip": "203.0.113.66",
                "srcuser": "www-data",
                "file_hash": EICAR_SHA256,
                "file_path": "/var/www/html/uploads/shell.php",
            },
            "full_log": (
                "Reverse shell spawned by a web-server child process from /var/www/html/uploads/shell.php; "
                "uploaded file matches the EICAR test file (lab stand-in for the web shell)."
            ),
        },
    },
    {
        "scenario": "recon",
        "type": "Reconnaissance (Low, unknown IOCs, monitoring)",
        "expected": "Low telemetry with IOCs that have no threat-intel evidence, so it stays for monitoring.",
        "payload": {
            "rule": {"id": "100500", "level": 3, "description": "Port scan detected against the DMZ gateway"},
            "agent": {"id": "003", "name": "dmz-fw01", "ip": "10.0.3.1"},
            "data": {"srcip": "192.0.2.200", "srchost": "probe-17.scanner.example", "dstport": "22,80,443,3389"},
            "full_log": "Sequential TCP SYN probes to 4 ports from 192.0.2.200 within 3 seconds.",
        },
    },
]


def seed_playbooks(db: Session) -> int:
    existing = {p.name for p in db.query(Playbook).all()}
    for pb in PRECONFIGURED_PLAYBOOKS:
        if pb["name"] not in existing:
            create_playbook(db, pb)
    return db.query(Playbook).count()


@router.post("/seed", status_code=status.HTTP_201_CREATED)
def seed_demo_data(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    """Seed the playbook catalogue and run four lab alerts through the real ingestion pipeline.

    Admin only. Returns 409 unless simulation mode is on.
    """
    if not is_simulation_mode(db):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Demo seeding is only available in simulation mode (ORCHESTRATION.simulation_mode=true).",
        )

    from backend.routers.logs import record_log

    playbook_count = seed_playbooks(db)
    record_log(
        db, source="AUTOMATION", level="INFO",
        message=f"Lab demo seeding started by {current_user.username}: {len(LAB_SCENARIOS)} lab alerts through the ingestion pipeline.",
        target="demo/seed",
        details={"requested_by": current_user.username, "scenarios": [s["scenario"] for s in LAB_SCENARIOS]},
    )

    seeded = []
    for scenario in LAB_SCENARIOS:
        result = ingest_alert_with_details(db, copy.deepcopy(scenario["payload"]), "demo")
        alert = result.alert
        seeded.append({
            "alert_id": alert.alert_id,
            "scenario": scenario["scenario"],
            "type": scenario["type"],
            "expected": scenario["expected"],
            "severity": alert.severity,
            "status": alert.status,
            "processing": result.processing,
            "ioc_verdicts": {a["value"]: a["verdict"] for a in result.artifacts},
            "max_threat_score": max((a["threat_score"] for a in result.artifacts), default=0),
        })

    return {
        "status": "Success",
        "message": (
            f"Playbook catalogue ready ({playbook_count} playbooks); ran {len(seeded)} lab alerts through the "
            "real ingestion pipeline. Threat-intel results are simulation-mode lab fixtures; connector "
            "actions are simulated unless the connector is configured."
        ),
        "simulation_mode": True,
        "seeded_playbooks_count": playbook_count,
        "seeded_alerts": seeded,
    }
