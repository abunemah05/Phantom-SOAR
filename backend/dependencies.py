"""Authentication and RBAC dependencies.

Every protected route resolves the caller from a signed Bearer JWT. There is no
fallback identity: a missing, malformed, expired or revoked token is a 401.
"""
import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, Iterable, Optional

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.security import decode_access_token, is_token_revoked, PASSWORD_CHANGE_CLAIM

logger = logging.getLogger(__name__)

security_bearer = HTTPBearer(auto_error=False)

# --- Roles -------------------------------------------------------------------
# Canonical role names, plus the legacy strings already stored in existing
# databases and offered by older UI builds. Matching is exact (case and
# whitespace normalised), never substring based.
ROLE_ADMIN = "Admin"
ROLE_SECURITY_ENGINEER = "Security Engineer"
ROLE_SOC_ANALYST = "SOC Analyst"
ROLE_AUDITOR = "SOC Auditor (Read-Only)"
ROLE_AI_AGENT = "AI Agent"

CANONICAL_ROLES = (ROLE_ADMIN, ROLE_SECURITY_ENGINEER, ROLE_SOC_ANALYST, ROLE_AUDITOR)


def normalize_role(role: Optional[str]) -> str:
    return " ".join((role or "").split()).casefold()


def _role_set(*names: str) -> FrozenSet[str]:
    return frozenset(normalize_role(n) for n in names)


ADMIN_ROLES = _role_set(
    ROLE_ADMIN,
    "Administrator",
    "System Administrator",
    "Sys Admin",
    "Lead SOC Architect / Admin",
    "SOC Lead / Admin",
    "SOC Lead / Incident Commander",
)
SECURITY_ENGINEER_ROLES = _role_set(
    ROLE_SECURITY_ENGINEER,
    "Sec Eng",
)
ANALYST_ROLES = _role_set(
    ROLE_SOC_ANALYST,
    "SOC Analyst Tier 1",
    "SOC Analyst Tier 2",
    "Tier 1 Analyst",
    "Tier 2 Analyst",
    "Tier 1 Analyst (Triage & Monitoring)",
    "Tier 2 Analyst (Senior Responder)",
    "Tier 2 Analyst (Senior)",
    "Threat Hunter / Intel Specialist",
    "SOC L1",
    "SOC L2",
)
READ_ONLY_ROLES = _role_set(ROLE_AUDITOR, "Auditor", "Read-Only")
SERVICE_ROLES = _role_set(ROLE_AI_AGENT, "Service Account")

PLAYBOOK_ENGINEER_ROLES = ADMIN_ROLES | SECURITY_ENGINEER_ROLES
OPERATOR_ROLES = ADMIN_ROLES | SECURITY_ENGINEER_ROLES | ANALYST_ROLES
KNOWN_ROLES = OPERATOR_ROLES | READ_ONLY_ROLES | SERVICE_ROLES


def role_level(role: Optional[str]) -> str:
    """'admin' | 'security_engineer' | 'analyst' | 'read_only' | 'service' | 'unknown'."""
    r = normalize_role(role)
    if r in ADMIN_ROLES:
        return "admin"
    if r in SECURITY_ENGINEER_ROLES:
        return "security_engineer"
    if r in ANALYST_ROLES:
        return "analyst"
    if r in READ_ONLY_ROLES:
        return "read_only"
    if r in SERVICE_ROLES:
        return "service"
    return "unknown"


def has_role(user: User, allowed: Iterable[str]) -> bool:
    return normalize_role(user.role) in allowed


def is_admin(user: User) -> bool:
    return has_role(user, ADMIN_ROLES)


def is_known_role(role: Optional[str]) -> bool:
    return normalize_role(role) in KNOWN_ROLES


def role_catalog() -> list:
    """Canonical assignable roles with their access level (legacy aliases are still accepted)."""
    return [{"role": r, "level": role_level(r)} for r in CANONICAL_ROLES]


# --- Authentication ------------------------------------------------------------
def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def get_token_payload(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    """Validated JWT claims of the caller. 401 when the token is missing, invalid, expired or revoked."""
    if auth is None or not auth.credentials or (auth.scheme or "").lower() != "bearer":
        raise _unauthorized("Authentication required: send 'Authorization: Bearer <token>'.")
    payload = decode_access_token(auth.credentials.strip())
    if not payload or not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise _unauthorized("Invalid or expired authentication token.")
    if is_token_revoked(payload):
        raise _unauthorized("This session has been signed out. Sign in again.")
    return payload


def _resolve_user(payload: Dict[str, Any], db: Session, allow_password_change_pending: bool) -> User:
    user = db.query(User).filter(User.username == payload["sub"]).first()
    if not user:
        raise _unauthorized("Invalid or expired authentication token.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator account is disabled.")
    if user.is_service_account:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Service accounts cannot use the operator API; authenticate to the agent API with an API key.",
        )

    # Tokens issued before the last password change (or admin reset) are no longer valid.
    changed_at = _as_utc(user.password_changed_at)
    issued_at = payload.get("iat")
    if changed_at is not None and isinstance(issued_at, (int, float)) and int(issued_at) < int(changed_at.timestamp()):
        raise _unauthorized("Session expired because the account password was changed. Sign in again.")

    if not allow_password_change_pending and (payload.get(PASSWORD_CHANGE_CLAIM) or user.compromised_reset_required):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before this account can use the console.",
        )
    return user


def get_current_user(
    payload: Dict[str, Any] = Depends(get_token_payload),
    db: Session = Depends(get_db),
) -> User:
    """Authenticated, active, human operator whose session is fully established."""
    return _resolve_user(payload, db, allow_password_change_pending=False)


def get_current_user_allow_password_change(
    payload: Dict[str, Any] = Depends(get_token_payload),
    db: Session = Depends(get_db),
) -> User:
    """Like get_current_user, but also accepts sessions that still have to change their password
    (used only by /auth/me and /auth/logout so the console can render the change-password screen)."""
    return _resolve_user(payload, db, allow_password_change_pending=True)


def require_human_analyst(current_user: User = Depends(get_current_user)) -> User:
    """Authenticated, active, non-service account. Used where a person must make the decision
    (approving containment, deciding on alerts, approving AI agent proposals)."""
    return current_user


def require_roles(allowed: FrozenSet[str], detail: str) -> Callable[..., User]:
    """Build a dependency that admits only users whose role is in `allowed`."""

    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if not has_role(current_user, allowed):
            logger.warning(
                f"RBAC denial: user '{current_user.username}' (role '{current_user.role}') - {detail}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{detail} Your current role is '{current_user.role}'.",
            )
        return current_user

    return _dependency


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Only SOC administrators."""
    if not has_role(current_user, ADMIN_ROLES):
        logger.warning(
            f"RBAC denial: user '{current_user.username}' (role '{current_user.role}') "
            f"attempted to access an administrative resource."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Operation requires SOC Administrator privileges. Your current role is '{current_user.role}'.",
        )
    return current_user


def require_sec_eng_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """Administrators and Security Engineers (playbook authoring, integration settings)."""
    if not has_role(current_user, PLAYBOOK_ENGINEER_ROLES):
        logger.warning(
            f"RBAC denial: user '{current_user.username}' (role '{current_user.role}') "
            f"attempted to modify playbook automation workflows."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Playbook modifications are restricted to System Administrators and Security Engineers. Your current role is '{current_user.role}'.",
        )
    return current_user


def require_analyst_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """Operators who may act on alerts: analysts, security engineers and administrators
    (read-only auditors and unrecognised roles are denied)."""
    if not has_role(current_user, OPERATOR_ROLES):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: this action requires a SOC Analyst, Security Engineer or Administrator role. Your current role is '{current_user.role}'.",
        )
    return current_user


def require_ingest_token(
    x_phantom_ingest_token: Optional[str] = Header(default=None, alias="X-Phantom-Ingest-Token")
) -> None:
    """Authenticate SIEM / EDR / XDR webhook senders with a shared ingestion token.

    Ingestion is disabled until PHANTOM_INGEST_TOKEN is set, so a fresh install never
    accepts unauthenticated alerts that can trigger containment.
    """
    expected = os.getenv("PHANTOM_INGEST_TOKEN", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook ingestion is disabled: set PHANTOM_INGEST_TOKEN on the server.",
        )
    if not x_phantom_ingest_token or not hmac.compare_digest(
        x_phantom_ingest_token.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Phantom-Ingest-Token header.",
        )
