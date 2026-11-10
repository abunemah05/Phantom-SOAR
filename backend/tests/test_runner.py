import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Alert, IocArtifact, Playbook
from backend.engine.runner import evaluate_execution_mode, process_alert, approve_and_contain_alert
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS
from backend.crud import create_alert, create_ioc_artifact, create_playbook

def test_evaluate_execution_mode():
    # Critical -> HOTL
    assert evaluate_execution_mode("Critical", 20) == "HOTL"
    # High -> HOTL
    assert evaluate_execution_mode("High", 10) == "HOTL"
    # VT score > 50 -> HOTL
    assert evaluate_execution_mode("Medium", 75) == "HOTL"
    # Low + low score -> HITL
    assert evaluate_execution_mode("Low", 15) == "HITL"
    # Medium + low score -> HITL
    assert evaluate_execution_mode("Medium", 30) == "HITL"

def test_runner_hotl_and_hitl_flow(tmp_path):
    test_db_file = tmp_path / "test.db"
    test_engine = create_engine(f"sqlite:///{test_db_file}")
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Monkeypatch SessionLocal in runner
    import backend.engine.runner as runner_module
    old_session = runner_module.SessionLocal
    runner_module.SessionLocal = TestingSession

    try:
        db = TestingSession()

        # Seed playbooks
        for pb in PRECONFIGURED_PLAYBOOKS:
            create_playbook(db, pb)

        # 1. Critical Ransomware alert (should force HOTL)
        alert_hotl = create_alert(db, {
            "rule_id": "TEST-RANSOM-01",
            "source": "Wazuh",
            "severity": "Critical",
            "status": "New",
            "raw_payload": {"rule": {"description": "Ransomware detection"}}
        })
        create_ioc_artifact(db, alert_hotl.alert_id, "IP", "198.51.100.45", threat_score=95)

        res_hotl = process_alert(alert_hotl.alert_id)
        assert res_hotl["status"] == "Contained"
        assert res_hotl["mode"] == "HOTL"
        assert res_hotl["mttr_seconds"] > 0
        assert os.path.exists(res_hotl["pdf_path"])

        # 2. Medium Phishing alert (should force HITL)
        alert_hitl = create_alert(db, {
            "rule_id": "TEST-PHISH-01",
            "source": "Wazuh",
            "severity": "Medium",
            "status": "New",
            "raw_payload": {"rule": {"description": "Suspicious email link"}}
        })
        create_ioc_artifact(db, alert_hitl.alert_id, "URL", "http://example.com/login", threat_score=30)

        res_hitl = process_alert(alert_hitl.alert_id)
        assert res_hitl["status"] == "Triaged"
        assert res_hitl["mode"] == "HITL"

        # Now test manual analyst approval
        res_approve = approve_and_contain_alert(db, alert_hitl.alert_id)
        assert res_approve["status"] == "Contained"
        assert res_approve["mttr_seconds"] > 0
        assert os.path.exists(res_approve["pdf_path"])

        db.close()
    finally:
        runner_module.SessionLocal = old_session
