import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.crud import (
    create_playbook,
    delete_playbook,
    get_playbook,
    get_playbooks,
    toggle_playbook_status,
    update_playbook,
)
from backend.database import get_db
from backend.dependencies import get_current_user, require_sec_eng_or_admin
from backend.engine.actions import PSEUDO_STEPS, list_actions, validate_workflow_steps
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS
from backend.models import User
from backend.schemas import PlaybookCreate, PlaybookUpdate

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])

EXECUTION_MODES = {"HOTL", "HITL"}


def _normalize_workflow(workflow_logic: Any) -> Any:
    if isinstance(workflow_logic, str):
        try:
            workflow_logic = json.loads(workflow_logic)
        except ValueError:
            raise HTTPException(status_code=422, detail="workflow_logic must be a JSON object.")
    errors = validate_workflow_steps(workflow_logic)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid playbook steps.", "errors": errors,
                    "allowed_actions": [a["name"] for a in list_actions()],
                    "pseudo_steps": sorted(PSEUDO_STEPS)},
        )
    return workflow_logic


def _normalize_mode(mode: Any) -> str:
    value = str(mode or "").strip().upper()
    if value not in EXECUTION_MODES:
        raise HTTPException(status_code=422, detail="execution_mode must be 'HOTL' or 'HITL'.")
    return value


@router.get("/templates")
def list_playbook_templates(current_user: User = Depends(get_current_user)):
    """Pre-configured SANS / MITRE playbook templates."""
    return PRECONFIGURED_PLAYBOOKS


@router.get("/actions")
def list_playbook_actions(current_user: User = Depends(get_current_user)):
    """Actions a playbook step may use, plus the pseudo-steps the runner understands."""
    return {"actions": list_actions(), "pseudo_steps": PSEUDO_STEPS}


@router.get("")
def list_playbooks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    active_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List registered playbooks."""
    playbooks = get_playbooks(db, skip=skip, limit=limit, active_only=active_only)
    return [p.to_dict() for p in playbooks]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_new_playbook(
    playbook_in: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Create a playbook (administrators and security engineers). Steps are validated against the action catalog."""
    playbook_in.workflow_logic = _normalize_workflow(playbook_in.workflow_logic)
    playbook_in.execution_mode = _normalize_mode(playbook_in.execution_mode)
    created = create_playbook(db, playbook_in)
    return created.to_dict()


@router.get("/{playbook_id}")
def get_single_playbook(playbook_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    playbook = get_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return playbook.to_dict()


@router.put("/{playbook_id}")
def update_existing_playbook(
    playbook_id: int,
    playbook_in: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Update a playbook (administrators and security engineers)."""
    if playbook_in.workflow_logic is not None:
        playbook_in.workflow_logic = _normalize_workflow(playbook_in.workflow_logic)
    if playbook_in.execution_mode is not None:
        playbook_in.execution_mode = _normalize_mode(playbook_in.execution_mode)
    updated = update_playbook(db, playbook_id, playbook_in)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return updated.to_dict()


@router.delete("/{playbook_id}")
def remove_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Delete a playbook (administrators and security engineers)."""
    if not delete_playbook(db, playbook_id):
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return {"status": "Success", "message": f"Playbook #{playbook_id} deleted"}


@router.patch("/{playbook_id}/toggle")
def toggle_status(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Enable or disable a playbook (administrators and security engineers)."""
    updated = toggle_playbook_status(db, playbook_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return {"status": "Success", "playbook_id": updated.playbook_id, "is_active": updated.is_active}
