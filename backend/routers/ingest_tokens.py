"""Admin management of per-sender webhook ingest tokens.

Each SIEM / EDR / XDR sender gets its own token so one leaked credential can be revoked without
touching the others. The plaintext token is returned exactly once, at creation; only a SHA-256
digest is stored (the tokens carry 256 bits of entropy, so no password stretching is needed).
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import require_admin
from backend.models import User
from backend.routers.logs import record_log
from backend.security import generate_ingest_token
from backend.security_models import IngestToken

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest-tokens", tags=["Webhook Ingest Tokens (Admin Only)"])


class IngestTokenCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100, description="Sender label, e.g. 'wazuh-prod-manager'")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=3650)


class IngestTokenInfo(BaseModel):
    id: int
    name: str
    token_prefix: str
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    status: str  # active | revoked | expired


class IngestTokenCreated(IngestTokenInfo):
    token: str  # shown once


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _status(row: IngestToken) -> str:
    if row.revoked_at is not None:
        return "revoked"
    if row.expires_at is not None and row.expires_at <= datetime.now(timezone.utc).replace(tzinfo=None):
        return "expired"
    return "active"


def _info(row: IngestToken) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "token_prefix": row.lookup_prefix,
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "last_used_at": _iso(row.last_used_at),
        "expires_at": _iso(row.expires_at),
        "revoked_at": _iso(row.revoked_at),
        "status": _status(row),
    }


@router.post("", response_model=IngestTokenCreated, status_code=status.HTTP_201_CREATED)
def create_ingest_token(
    payload: IngestTokenCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """[Admin Only] Create a token for one sender. The token is shown once and cannot be retrieved later."""
    name = " ".join(payload.name.split())
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty.")
    duplicate = db.query(IngestToken).filter(
        func.lower(IngestToken.name) == name.lower(), IngestToken.revoked_at.is_(None)
    ).first()
    if duplicate:
        raise HTTPException(status_code=400, detail=f"An active ingest token named '{name}' already exists; revoke it first or pick another name.")

    token, prefix, digest = generate_ingest_token()
    while db.query(IngestToken).filter(IngestToken.lookup_prefix == prefix).first():
        token, prefix, digest = generate_ingest_token()
    expires = None
    if payload.expires_in_days:
        expires = (datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)).replace(tzinfo=None)
    row = IngestToken(name=name, token_hash=digest, lookup_prefix=prefix, created_by=admin.username, expires_at=expires)
    db.add(row)
    db.commit()
    db.refresh(row)
    record_log(db, "AUTH", "ACTION", f"Admin '{admin.username}' created ingest token '{name}' ({prefix}).",
               target=name, details={"by": admin.username, "token_prefix": prefix, "expires_at": _iso(expires)})
    return {**_info(row), "token": token}


@router.get("", response_model=List[IngestTokenInfo])
def list_ingest_tokens(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """[Admin Only] Tokens with last-use time and status. Digests and plaintext are never returned."""
    return [_info(r) for r in db.query(IngestToken).order_by(IngestToken.id.desc()).all()]


@router.post("/{token_id}/revoke", response_model=IngestTokenInfo)
def revoke_ingest_token(token_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """[Admin Only] Revoke a token immediately. The row is kept for the audit trail."""
    row = db.query(IngestToken).filter(IngestToken.id == token_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Ingest token not found.")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
        db.refresh(row)
        record_log(db, "AUTH", "WARNING", f"Admin '{admin.username}' revoked ingest token '{row.name}' ({row.lookup_prefix}).",
                   target=row.name, details={"by": admin.username, "token_prefix": row.lookup_prefix})
    return _info(row)
