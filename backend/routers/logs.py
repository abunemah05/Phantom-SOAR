import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.database import get_db
from backend.models import SystemLog, User
from backend.dependencies import get_current_user, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Telemetry & Audit Logs"])

LOG_LEVELS = {"INFO", "WARNING", "ERROR", "CRITICAL", "ACTION"}


class LogCreateRequest(BaseModel):
    source: str = Field(min_length=1, max_length=50)  # EDR, XDR, SIEM, TIP, FIREWALL, IAM, ITSM, AUTOMATION
    level: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL, ACTION
    message: str = Field(min_length=1, max_length=5000)
    target: Optional[str] = Field(default=None, max_length=200)
    details: Optional[Dict[str, Any]] = None

    @field_validator("level")
    @classmethod
    def _level(cls, v: str) -> str:
        v = (v or "").strip().upper()
        if v not in LOG_LEVELS:
            raise ValueError(f"level must be one of {sorted(LOG_LEVELS)}")
        return v


def get_naive_utc():
    """Naive UTC timestamp (SQLite stores datetimes without a timezone)."""
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
    """Persist a system / audit log event."""
    log_entry = SystemLog(
        source=source.upper(),
        level=level.upper(),
        message=message,
        target=target[:200] if target else target,
        details=details or {},
        created_at=created_at or get_naive_utc()
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry


@router.get("")
def list_logs(
    source: Optional[str] = Query(None, description="Filter by source: EDR, XDR, SIEM, TIP, FIREWALL, IAM, ITSM, AUTOMATION, AUTH, RBAC"),
    seconds: Optional[int] = Query(None, ge=1, description="Only logs from the last N seconds (e.g. 30, 60, 300, 3600)"),
    level: Optional[str] = Query(None, description="Filter by level: INFO, WARNING, ERROR, CRITICAL, ACTION"),
    search: Optional[str] = Query(None, description="Search across messages, targets and sources"),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Unified SOC audit and telemetry log, filterable by source, level, age and keyword."""
    query = db.query(SystemLog)

    if source and source.strip() and source.upper() != "ALL":
        query = query.filter(SystemLog.source == source.strip().upper())

    if seconds is not None and seconds > 0:
        cutoff = get_naive_utc() - timedelta(seconds=seconds)
        query = query.filter(SystemLog.created_at >= cutoff)

    if level and level.strip() and level.upper() != "ALL":
        query = query.filter(SystemLog.level == level.strip().upper())

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SystemLog.message.ilike(term),
                SystemLog.target.ilike(term),
                SystemLog.source.ilike(term)
            )
        )

    logs = query.order_by(SystemLog.created_at.desc(), SystemLog.log_id.desc()).limit(limit).all()
    return [entry.to_dict() for entry in logs]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_log(
    payload: LogCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """[Admin Only] Append a manual log entry. The author is recorded in details.recorded_by."""
    details = dict(payload.details or {})
    details["recorded_by"] = admin.username
    entry = record_log(
        db=db,
        source=payload.source.strip(),
        level=payload.level,
        message=payload.message,
        target=payload.target,
        details=details
    )
    return entry.to_dict()


@router.delete("")
def clear_logs(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """[Admin Only] Purge all logs. The purge itself is recorded as the first entry of the new log."""
    deleted = db.query(SystemLog).delete()
    db.commit()
    record_log(db, "AUDIT", "WARNING", f"Admin '{admin.username}' cleared the log ({deleted} entries).",
               target=admin.username, details={"deleted": deleted, "by": admin.username})
    return {"status": "Success", "message": f"Cleared {deleted} log entries.", "deleted": deleted}
