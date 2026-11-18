"""Tables owned by the security layer (kept apart from models.py).

Listed in backend.db_migrate.MODEL_MODULES so Alembic and create_all know these tables (migration 0003).
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, ForeignKey, Integer, String, UniqueConstraint

from backend import models as _models  # noqa: F401  (registers users so the foreign key resolves)
from backend.database import Base, UTCDateTime, engine

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IngestToken(Base):
    """Per-sender credential for the /webhooks endpoints. Only a SHA-256 digest is stored."""
    __tablename__ = "ingest_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False)
    lookup_prefix = Column(String(16), nullable=False, index=True)
    created_by = Column(String(50), nullable=True)
    created_at = Column(UTCDateTime, default=_utc_now, nullable=False)
    last_used_at = Column(UTCDateTime, nullable=True)
    revoked_at = Column(UTCDateTime, nullable=True)
    expires_at = Column(UTCDateTime, nullable=True)


class RevokedToken(Base):
    """JWT ids revoked at logout / password change, kept until the token would have expired anyway."""
    __tablename__ = "revoked_tokens"

    jti = Column(String(64), primary_key=True)
    expires_at = Column(UTCDateTime, nullable=False, index=True)


class ServiceAccountPolicy(Base):
    """Expiry and source-IP restrictions of a service account's API key, plus last-use bookkeeping."""
    __tablename__ = "service_account_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE", name="fk_service_account_policies_user_id"), nullable=False, unique=True, index=True)
    expires_at = Column(UTCDateTime, nullable=True)
    ip_allowlist = Column(JSON, nullable=True)  # list of IPs / CIDRs; empty or null = any address
    last_used_at = Column(UTCDateTime, nullable=True)
    last_used_ip = Column(String(64), nullable=True)


class UsedTotpCode(Base):
    """TOTP time steps already consumed per subject (replay protection, RFC 6238 section 5.2)."""
    __tablename__ = "used_totp_codes"
    __table_args__ = (UniqueConstraint("subject", "time_step", name="uq_used_totp_subject_step"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    subject = Column(String(100), nullable=False, index=True)
    time_step = Column(Integer, nullable=False)
    used_at = Column(UTCDateTime, default=_utc_now, nullable=False, index=True)


SECURITY_TABLES = [
    IngestToken.__table__,
    RevokedToken.__table__,
    ServiceAccountPolicy.__table__,
    UsedTotpCode.__table__,
]

_ensured = False


def ensure_tables() -> None:
    """Create the security tables if missing (development / test convenience; production uses migrations)."""
    global _ensured
    if _ensured:
        return
    try:
        Base.metadata.create_all(bind=engine, tables=SECURITY_TABLES)
        _ensured = True
    except Exception as exc:  # pragma: no cover - DB unavailable
        logger.error(f"Could not create security tables: {exc}")
