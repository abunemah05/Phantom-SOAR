from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Playbook, User
from backend.dependencies import require_sec_eng_or_admin
from backend.schemas import PlaybookCreate, PlaybookUpdate, PlaybookResponse
from backend.crud import (
    get_playbook,
    get_playbooks,
    create_playbook,
    update_playbook,
    delete_playbook,
    toggle_playbook_status
)
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])

@router.get("/templates")
def list_playbook_templates():
    """Retrieve 12 pre-configured SANS / MITRE playbook templates."""
    return PRECONFIGURED_PLAYBOOKS

@router.get("")
def list_playbooks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    active_only: bool = False,
    db: Session = Depends(get_db)
):
    """List all active or registered playbooks."""
    playbooks = get_playbooks(db, skip=skip, limit=limit, active_only=active_only)
    return [p.to_dict() for p in playbooks]

@router.post("", status_code=status.HTTP_201_CREATED)
def create_new_playbook(
    playbook_in: PlaybookCreate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin)
):
    """
    Create a new automation playbook.
    Restricted to System Administrators and Security Engineers.
    """
    created = create_playbook(db, playbook_in)
    return created.to_dict()

@router.get("/{playbook_id}")
def get_single_playbook(playbook_id: int, db: Session = Depends(get_db)):
    """Get single playbook by ID."""
    playbook = get_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return playbook.to_dict()

@router.put("/{playbook_id}")
def update_existing_playbook(
    playbook_id: int,
    playbook_in: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin)
):
    """
    Update playbook properties, metadata, or JSON workflow logic.
    Restricted to System Administrators and Security Engineers.
    """
    updated = update_playbook(db, playbook_id, playbook_in)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return updated.to_dict()

@router.delete("/{playbook_id}")
def remove_playbook(
    playbook_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin)
):
    """
    Delete a playbook by ID.
    Restricted to System Administrators and Security Engineers.
    """
    success = delete_playbook(db, playbook_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return {"status": "Success", "message": f"Playbook #{playbook_id} deleted"}

@router.patch("/{playbook_id}/toggle")
def toggle_status(
    playbook_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin)
):
    """
    Toggle the is_active status of a playbook.
    Restricted to System Administrators and Security Engineers.
    """
    updated = toggle_playbook_status(db, playbook_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return {
        "status": "Success",
        "playbook_id": updated.playbook_id,
        "is_active": updated.is_active
    }
