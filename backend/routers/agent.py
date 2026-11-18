"""AI triage and agent API.

Operator endpoints (signed-in user, Bearer JWT):
    GET  /agent/status                      any signed-in user
    GET  /agent/proposals                   any signed-in user
    GET  /agent/proposals/{id}              any signed-in user
    POST /agent/triage/{alert_id}           responder (analyst, security engineer, admin)
    POST /agent/proposals/{id}/approve      responder; a person decides, never a service account
    POST /agent/proposals/{id}/reject       responder

Agent endpoints (service-account API key, header X-Phantom-Agent-Key; operator JWTs are NOT accepted):
    GET  /agent/queue
    GET  /agent/alerts/{id}                 redacted alert context
    GET  /agent/actions                     action catalog
    POST /agent/alerts/{id}/proposals       submit a proposal; every action goes through the policy engine

The routes carry their own dependency (not a router-level one) because the two groups authenticate differently.
Policy is the only gate for execution: see backend/engine/ai_triage.py.
"""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from backend.crud import get_alert, get_alerts
from backend.database import get_db
from backend.dependencies import get_current_service_account, get_current_user
from backend.engine import ai_triage
from backend.engine.actions import list_actions
from backend.models import AgentProposal, User
from backend.routers.alerts import require_responder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["AI Triage & Agent API"])


def _http_error(exc: ai_triage.AITriageError) -> HTTPException:
    headers = {"Retry-After": str(int(exc.retry_after) + 1)} if exc.retry_after and exc.http_status == 409 else None
    return HTTPException(status_code=exc.http_status, detail=exc.message, headers=headers)


def _alert_or_404(db: Session, alert_id: int):
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")
    return alert


# --- Operator endpoints -----------------------------------------------------------------------------------------

@router.get("/status")
def agent_status(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """AI triage settings and counters. The API key is never returned (only whether and where one is set)."""
    return ai_triage.ai_status(db)


@router.get("/proposals")
def list_proposals(
    status: Optional[str] = Query(None, description="Only proposals with this status"),
    alert_id: Optional[int] = Query(None, description="Only proposals for this alert"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(AgentProposal)
    if status and status.strip() and status.strip().lower() != "all":
        query = query.filter(AgentProposal.status == status.strip().lower())
    if alert_id is not None:
        query = query.filter(AgentProposal.alert_id == alert_id)
    total = query.count()
    rows = (
        query.order_by(AgentProposal.created_at.desc(), AgentProposal.proposal_id.desc())
        .offset(offset).limit(limit).all()
    )
    return {"items": [p.to_dict() for p in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/proposals/{proposal_id}")
def get_proposal(proposal_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    proposal = db.query(AgentProposal).filter(AgentProposal.proposal_id == proposal_id).first()
    if proposal is None:
        raise HTTPException(status_code=404, detail=f"Proposal #{proposal_id} not found")
    return proposal.to_dict()


@router.post("/triage/{alert_id}", status_code=201)
def triage_alert(alert_id: int, db: Session = Depends(get_db), user: User = Depends(require_responder)):
    """Ask the configured model to triage one alert. 409 when AI is disabled, no key is set, the per-minute
    budget is used up or the alert is busy; 502 with a safe message when the model call fails."""
    try:
        proposal = ai_triage.run_triage(db, alert_id, trigger="manual", requested_by=user.username)
    except ai_triage.AITriageError as exc:
        raise _http_error(exc)
    return proposal.to_dict()


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notes: Optional[str] = Field(default=None, max_length=1000)


class ApproveBody(DecisionBody):
    action_indexes: Optional[List[int]] = Field(default=None, max_length=ai_triage.MAX_ACTIONS)


@router.post("/proposals/{proposal_id}/approve")
def approve_proposal(
    proposal_id: int,
    body: Optional[ApproveBody] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_responder),
):
    """Approve a pending proposal and run its (selected) actions as this analyst. 409 when already decided."""
    body = body or ApproveBody()
    try:
        proposal, results = ai_triage.approve_proposal(db, proposal_id, user.username, body.notes, body.action_indexes)
    except ai_triage.AITriageError as exc:
        raise _http_error(exc)
    return {"proposal": proposal.to_dict(), "results": results}


@router.post("/proposals/{proposal_id}/reject")
def reject_proposal(
    proposal_id: int,
    body: Optional[DecisionBody] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_responder),
):
    try:
        proposal = ai_triage.reject_proposal(db, proposal_id, user.username, (body or DecisionBody()).notes)
    except ai_triage.AITriageError as exc:
        raise _http_error(exc)
    return proposal.to_dict()


# --- Agent (API key) endpoints ----------------------------------------------------------------------------------

@router.get("/queue")
def agent_queue(
    status: str = Query("New", max_length=30),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    agent: User = Depends(get_current_service_account),
):
    """Alerts waiting for an agent (default: status New), newest first."""
    alerts = get_alerts(db, skip=0, limit=limit, status=status)
    return {"items": [
        {"alert_id": a.alert_id, "rule_id": a.rule_id, "severity": a.severity, "status": a.status,
         "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in alerts
    ]}


@router.get("/alerts/{alert_id}")
def agent_alert_context(alert_id: int, db: Session = Depends(get_db), agent: User = Depends(get_current_service_account)):
    """Redacted alert context (no secrets, no e-mail addresses; the raw payload only when ai_send_raw_payload is on)."""
    alert = _alert_or_404(db, alert_id)
    context, _aliases = ai_triage.build_alert_context(db, alert)
    return context


@router.get("/actions")
def agent_actions(agent: User = Depends(get_current_service_account)):
    """The action catalog: names, target types, impact and parameters."""
    return {"items": list_actions()}


@router.post("/alerts/{alert_id}/proposals", status_code=201)
def submit_agent_proposal(
    alert_id: int,
    payload: ai_triage.ProposalIn,
    db: Session = Depends(get_db),
    agent: User = Depends(get_current_service_account),
):
    """Submit a verdict and proposed actions. Every action is evaluated with actor="agent"; actions that policy
    allows without approval run (live or simulated per simulation mode), the rest wait for a human."""
    alert = _alert_or_404(db, alert_id)
    proposal = ai_triage.submit_proposal(
        db, alert, payload, agent_name=agent.username, executed_by=agent.username,
        alias_back=ai_triage.alias_back_for_alert(db, alert), origin="agent-api",
    )
    return proposal.to_dict()
