from typing import List, Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

# --- Auth & User Schemas (NIST SP 800-63B Compliant) ---
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None  # Optional for single-factor, required when MFA is enabled

class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: str

class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    issuer: str
    account: str
    message: str

class MFAVerifyRequest(BaseModel):
    username: Optional[str] = None
    code: str

class MFAStatusResponse(BaseModel):
    mfa_enabled: bool
    status: str
    message: str

class UserResponse(BaseModel):
    user_id: int
    username: str
    role: str
    must_change_password: bool = False
    is_active: bool = True
    mfa_enabled: bool = False
    compromised_reset_required: bool = False
    password_changed_at: Optional[str] = None
    created_at: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class UserCreateRequest(BaseModel):
    username: str
    role: str = "SOC Analyst"
    mfa_enabled: bool = False

class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    compromised_reset_required: Optional[bool] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: bool = False
    user: UserResponse


# --- RBAC Admin Reporting Schemas ---
class AnalystMetrics(BaseModel):
    analyst_username: str
    role: str
    cases_assigned: int = 0
    cases_resolved: int = 0
    escalated_count: int = 0
    monitored_count: int = 0
    dismissed_count: int = 0
    containment_actions_taken: int = 0
    avg_mttr_seconds: float = 0.0

class AdminReportFilterRequest(BaseModel):
    analyst: Optional[str] = None  # username or "all"
    period: Optional[str] = "month"  # "day", "week", "month", "custom"
    start_date: Optional[str] = None  # YYYY-MM-DD or ISO string
    end_date: Optional[str] = None  # YYYY-MM-DD or ISO string

class AdminReportResponse(BaseModel):
    period: str
    start_date: str
    end_date: str
    filtered_analyst: Optional[str] = None
    total_cases_reviewed: int
    total_containment_actions: int
    average_mttr_seconds: float
    analyst_breakdown: List[AnalystMetrics]
    cases: List[Dict[str, Any]]
    action_logs: List[Dict[str, Any]]


# --- System Configuration Schemas ---
class ConfigItem(BaseModel):
    category: str  # AI, EDR, XDR, SIEM, TIP, FIREWALL, ITSM
    key_name: str
    key_value: str
    is_secret: bool = True

class ConfigUpdateRequest(BaseModel):
    configs: List[ConfigItem]

class TestConnectionRequest(BaseModel):
    category: str
    service_name: str
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None


# --- Alert Action Decision Schema ---
class AlertDecisionRequest(BaseModel):
    decision: str  # "take_action" | "keep_and_monitor" | "dismiss"
    notes: Optional[str] = None
    analyst_username: Optional[str] = None


# --- IoC Artifact Schemas ---
class IocArtifactBase(BaseModel):
    artifact_type: str  # IP, Hash, URL, Domain
    value: str
    threat_score: int = 0

class IocArtifactCreate(IocArtifactBase):
    alert_id: Optional[int] = None

class IocArtifactResponse(IocArtifactBase):
    artifact_id: int
    alert_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- Containment Action Schemas ---
class ContainmentActionBase(BaseModel):
    action_type: str
    status: str = "Executed"
    executed_by: str = "System"

class ContainmentActionCreate(ContainmentActionBase):
    alert_id: int

class ContainmentActionResponse(ContainmentActionBase):
    action_id: int
    alert_id: int
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


# --- Playbook Execution Schemas ---
class PlaybookExecutionBase(BaseModel):
    status: str = "Completed"
    mttr_seconds: float = 0.0

class PlaybookExecutionCreate(PlaybookExecutionBase):
    alert_id: int
    playbook_id: Optional[int] = None

class PlaybookExecutionResponse(PlaybookExecutionBase):
    execution_id: int
    alert_id: int
    playbook_id: Optional[int] = None
    playbook_name: Optional[str] = None
    executed_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- Incident Report Schemas ---
class IncidentReportResponse(BaseModel):
    report_id: int
    alert_id: int
    pdf_path: str
    generated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- Playbook Schemas ---
class PlaybookBase(BaseModel):
    name: str
    target_threat: str
    execution_mode: str = "HOTL"  # HOTL or HITL
    workflow_logic: Any
    is_active: bool = True

class PlaybookCreate(PlaybookBase):
    pass

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    target_threat: Optional[str] = None
    execution_mode: Optional[str] = None
    workflow_logic: Optional[Any] = None
    is_active: Optional[bool] = None

class PlaybookResponse(BaseModel):
    playbook_id: int
    name: str
    target_threat: str
    execution_mode: str
    workflow_logic: Any
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- Alert Schemas ---
class AlertBase(BaseModel):
    rule_id: str
    source: str = "Wazuh"
    severity: str  # Critical, High, Medium, Low
    status: str = "New"  # New, Triaged, Contained, Resolved, Closed, Monitoring
    analyst_decision: Optional[str] = None
    assigned_analyst: Optional[str] = None
    resolved_by: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None

class AlertCreate(AlertBase):
    pass

class AlertResponse(AlertBase):
    alert_id: int
    created_at: datetime
    resolved_at: Optional[datetime] = None
    ioc_count: int = 0
    max_threat_score: Optional[int] = 0
    model_config = ConfigDict(from_attributes=True)

class AlertDetailResponse(AlertResponse):
    ioc_artifacts: List[IocArtifactResponse] = []
    playbook_executions: List[PlaybookExecutionResponse] = []
    containment_actions: List[ContainmentActionResponse] = []
    incident_reports: List[IncidentReportResponse] = []
    mitre_attack: Optional[Dict[str, Any]] = None
    ai_summary: Optional[str] = None
    vulnerability_intel: Optional[Dict[str, Any]] = None
    model_config = ConfigDict(from_attributes=True)


# --- Webhook Schemas ---
class WazuhAlertPayload(BaseModel):
    rule: Optional[Dict[str, Any]] = Field(default_factory=dict)
    agent: Optional[Dict[str, Any]] = Field(default_factory=dict)
    data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    decoder: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[str] = None
    full_log: Optional[str] = None
    id: Optional[str] = None
    model_config = ConfigDict(extra="allow")


# --- Metrics Schemas ---
class DashboardMetrics(BaseModel):
    total_alerts: int
    new_alerts: int
    triaged_alerts: int
    contained_alerts: int
    resolved_alerts: int
    unresolved_alerts: int = 0
    review_gates_count: int = 0
    automated_actions: int
    avg_mttr_seconds: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
