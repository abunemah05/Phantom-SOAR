import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.database import get_db
from backend.models import SystemLog, User
from backend.dependencies import get_current_user
from backend.integration_config import get_setting

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Telemetry & Audit Logs"])

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


# --- Retention ---------------------------------------------------------------------------------
# The audit trail is append-only through the API for every role, administrators included: there is
# no endpoint that writes arbitrary entries, edits them or deletes them. The ONLY removal path is this
# age-based retention purge, called by the scheduled maintenance job, never by a request.
MIN_RETENTION_DAYS = 30
DEFAULT_RETENTION_DAYS = 365


def purge_expired_logs(db: Session, retention_days: Optional[int] = None, actor: str = "retention-job") -> int:
    """Delete log entries older than the retention period and record an audit entry about it.

    The period comes from `retention_days`, else the PHANTOM_LOG_RETENTION_DAYS setting (default 365).
    Anything below MIN_RETENTION_DAYS is refused so a typo cannot wipe the trail. Returns rows deleted.
    """
    if retention_days is None:
        raw = get_setting("phantom_log_retention_days", db=None) or str(DEFAULT_RETENTION_DAYS)
        try:
            retention_days = int(raw)
        except ValueError:
            logger.error(f"Invalid PHANTOM_LOG_RETENTION_DAYS={raw!r}; using {DEFAULT_RETENTION_DAYS}.")
            retention_days = DEFAULT_RETENTION_DAYS
    if retention_days < MIN_RETENTION_DAYS:
        raise ValueError(f"Log retention must be at least {MIN_RETENTION_DAYS} days (got {retention_days}).")
    cutoff = get_naive_utc() - timedelta(days=retention_days)
    deleted = db.query(SystemLog).filter(SystemLog.created_at < cutoff).delete(synchronize_session=False)
    db.commit()
    record_log(
        db, "AUDIT", "ACTION",
        f"Retention purge by '{actor}': removed {deleted} log entries older than {retention_days} days.",
        target=actor, details={"deleted": deleted, "retention_days": retention_days, "cutoff": cutoff.isoformat(), "by": actor},
    )
    return deleted
