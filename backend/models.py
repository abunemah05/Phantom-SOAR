from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, Text, JSON
from sqlalchemy.orm import relationship
from backend.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="SOC Lead / Admin", nullable=False)  # Admin vs SOC Analyst roles
    must_change_password = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # NIST SP 800-63B Authentication & MFA Additions
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(64), nullable=True)  # RFC 6238 TOTP Base32 secret
    password_changed_at = Column(DateTime, default=utc_now, nullable=False)
    compromised_reset_required = Column(Boolean, default=False, nullable=False)  # Resets ONLY on suspicion
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)  # Temporary rate-limiting against brute force

    # Service accounts (AI agents, integrations) authenticate with an API key instead of a password
    is_service_account = Column(Boolean, default=False, nullable=False)
    api_key_hash = Column(String(255), nullable=True)
    api_key_prefix = Column(String(16), nullable=True, index=True)

    created_at = Column(DateTime, default=utc_now, nullable=False)

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role,
            "must_change_password": self.must_change_password,
            "is_active": self.is_active,
            "mfa_enabled": self.mfa_enabled,
            "compromised_reset_required": self.compromised_reset_required,
            "is_service_account": bool(self.is_service_account),
            "password_changed_at": self.password_changed_at.isoformat() if self.password_changed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class SystemConfig(Base):
    __tablename__ = "system_configs"

    config_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    category = Column(String(50), index=True, nullable=False)  # AI, EDR, XDR, SIEM, TIP, FIREWALL, ITSM
    key_name = Column(String(100), index=True, nullable=False)
    key_value = Column(String(1000), default="", nullable=False)
    is_secret = Column(Boolean, default=True, nullable=False)
    updated_at = Column(DateTime, default=utc_now, nullable=False)

    def to_dict(self):
        return {
            "config_id": self.config_id,
            "category": self.category,
            "key_name": self.key_name,
            "key_value": self.key_value,
            "is_secret": self.is_secret,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rule_id = Column(String(100), index=True, nullable=False)
    source = Column(String(50), default="Wazuh", nullable=False)
    severity = Column(String(20), index=True, nullable=False)  # Critical, High, Medium, Low
    status = Column(String(20), index=True, default="New", nullable=False)  # New, Triaged, Contained, Resolved, Closed, Monitoring
    raw_payload = Column(JSON, nullable=True)
    analyst_decision = Column(String(100), nullable=True)  # "Kept as Benign / Monitoring", "Escalated & Contained", etc.

    # RBAC & Analyst Assignment Tracking
    assigned_analyst = Column(String(50), nullable=True, index=True)
    resolved_by = Column(String(50), nullable=True, index=True)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    ioc_artifacts = relationship("IocArtifact", back_populates="alert", cascade="all, delete-orphan")
    playbook_executions = relationship("PlaybookExecution", back_populates="alert", cascade="all, delete-orphan")
    containment_actions = relationship("ContainmentAction", back_populates="alert", cascade="all, delete-orphan")
    incident_reports = relationship("IncidentReport", back_populates="alert", cascade="all, delete-orphan")
    analyst_actions = relationship("AnalystActionLog", back_populates="alert", cascade="all, delete-orphan")
    agent_proposals = relationship("AgentProposal", back_populates="alert", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "source": self.source,
            "severity": self.severity,
            "status": self.status,
            "analyst_decision": self.analyst_decision,
            "assigned_analyst": self.assigned_analyst,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "raw_payload": self.raw_payload,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "ioc_count": len(self.ioc_artifacts) if self.ioc_artifacts else 0
        }


class IocArtifact(Base):
    __tablename__ = "ioc_artifacts"

    artifact_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(50), nullable=False)  # IP, Hash, URL, Domain
    value = Column(String(500), nullable=False, index=True)
    threat_score = Column(Integer, default=0, nullable=False)  # e.g., 0-100
    verdict = Column(String(20), default="Unknown", nullable=False)  # Malicious, Suspicious, Clean, Unknown
    enrichment_status = Column(String(30), default="pending", nullable=False)  # enriched, partial, unavailable, not_configured, pending
    tip_results = Column(JSON, nullable=True)  # per-provider results, each with its own status
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationship
    alert = relationship("Alert", back_populates="ioc_artifacts")

    def to_dict(self):
        return {
            "artifact_id": self.artifact_id,
            "alert_id": self.alert_id,
            "artifact_type": self.artifact_type,
            "value": self.value,
            "threat_score": self.threat_score,
            "verdict": self.verdict,
            "enrichment_status": self.enrichment_status,
            "tip_results": self.tip_results,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Playbook(Base):
    __tablename__ = "playbooks"

    playbook_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(150), nullable=False, index=True)
    target_threat = Column(String(100), nullable=False, index=True)
    execution_mode = Column(String(20), default="HOTL", nullable=False)  # HOTL or HITL
    workflow_logic = Column(Text, nullable=False)  # JSON or YAML string
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationship
    executions = relationship("PlaybookExecution", back_populates="playbook", cascade="all, delete-orphan")

    def to_dict(self):
        try:
            workflow = json.loads(self.workflow_logic) if isinstance(self.workflow_logic, str) else self.workflow_logic
        except Exception:
            workflow = self.workflow_logic
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "target_threat": self.target_threat,
            "execution_mode": self.execution_mode,
            "workflow_logic": workflow,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    execution_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.playbook_id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(50), default="Completed", nullable=False)
    mttr_seconds = Column(Float, default=0.0, nullable=False)
    executed_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    alert = relationship("Alert", back_populates="playbook_executions")
    playbook = relationship("Playbook", back_populates="executions")

    def to_dict(self):
        return {
            "execution_id": self.execution_id,
            "alert_id": self.alert_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook.name if self.playbook else None,
            "status": self.status,
            "mttr_seconds": self.mttr_seconds,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None
        }


class ContainmentAction(Base):
    __tablename__ = "containment_actions"

    action_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(100), nullable=False)  # isolate_endpoint, block_ip, terminate_session, disable_account
    status = Column(String(50), default="Executed", nullable=False)
    executed_by = Column(String(50), default="System", nullable=False, index=True)  # System or Analyst username
    target = Column(String(255), nullable=True)  # host, IP, user, or file the action was applied to
    connector = Column(String(50), nullable=True)  # edr, firewall, iam, itsm, ...
    execution_mode = Column(String(20), nullable=True)  # live, simulated, skipped, blocked
    details = Column(JSON, nullable=True)  # raw connector response / error / policy reasons
    timestamp = Column(DateTime, default=utc_now, nullable=False)

    # Relationship
    alert = relationship("Alert", back_populates="containment_actions")

    def to_dict(self):
        return {
            "action_id": self.action_id,
            "alert_id": self.alert_id,
            "action_type": self.action_type,
            "status": self.status,
            "executed_by": self.executed_by,
            "target": self.target,
            "connector": self.connector,
            "execution_mode": self.execution_mode,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class IncidentReport(Base):
    __tablename__ = "incident_reports"

    report_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True)
    pdf_path = Column(String(500), nullable=False)
    generated_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationship
    alert = relationship("Alert", back_populates="incident_reports")

    def to_dict(self):
        return {
            "report_id": self.report_id,
            "alert_id": self.alert_id,
            "pdf_path": self.pdf_path,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None
        }


class AnalystActionLog(Base):
    __tablename__ = "analyst_action_logs"

    log_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_username = Column(String(50), nullable=False, index=True)
    action_type = Column(String(100), nullable=False)  # "take_action", "keep_and_monitor", "approve", "dismiss"
    decision = Column(String(150), nullable=True)
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)

    # Relationship
    alert = relationship("Alert", back_populates="analyst_actions")

    def to_dict(self):
        return {
            "log_id": self.log_id,
            "alert_id": self.alert_id,
            "analyst_username": self.analyst_username,
            "action_type": self.action_type,
            "decision": self.decision,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class SystemLog(Base):
    __tablename__ = "system_logs"

    log_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source = Column(String(50), index=True, nullable=False)  # EDR, XDR, SIEM, TIP, FIREWALL, IAM, ITSM, AUTOMATION, AUTH, RBAC
    level = Column(String(20), index=True, default="INFO", nullable=False)  # INFO, WARNING, ERROR, CRITICAL, ACTION
    message = Column(Text, nullable=False)
    target = Column(String(200), nullable=True)  # IP, Hostname, User, Rule ID
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self):
        return {
            "log_id": self.log_id,
            "source": self.source,
            "level": self.level,
            "message": self.message,
            "target": self.target,
            "details": self.details,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class AgentProposal(Base):
    """A triage verdict and set of proposed response actions submitted by an AI agent.

    Every proposed action is checked by the policy engine; actions are only executed
    automatically when policy allows it, otherwise they wait for an analyst decision.
    """
    __tablename__ = "agent_proposals"

    proposal_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True)
    agent_name = Column(String(100), nullable=False, index=True)
    verdict = Column(String(20), nullable=False)  # malicious, suspicious, benign, unknown
    confidence = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    summary = Column(Text, nullable=True)
    reasoning = Column(Text, nullable=True)
    proposed_actions = Column(JSON, nullable=True)  # [{"action", "target", "params"}]
    policy_evaluation = Column(JSON, nullable=True)  # per-action policy decision
    execution_results = Column(JSON, nullable=True)
    status = Column(String(30), default="pending_approval", nullable=False, index=True)
    # pending_approval, auto_executed, partially_executed, approved, rejected, blocked, no_action
    decided_by = Column(String(50), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decision_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)

    alert = relationship("Alert", back_populates="agent_proposals")

    def to_dict(self):
        return {
            "proposal_id": self.proposal_id,
            "alert_id": self.alert_id,
            "agent_name": self.agent_name,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "summary": self.summary,
            "reasoning": self.reasoning,
            "proposed_actions": self.proposed_actions or [],
            "policy_evaluation": self.policy_evaluation or [],
            "execution_results": self.execution_results or [],
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_notes": self.decision_notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
