"""Authentication and RBAC dependencies.

Every protected route resolves the caller from a signed Bearer JWT. There is no
fallback identity: a missing, malformed, expired or revoked token is a 401.
"""
import hmac
import ipaddress
import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, Iterable, Optional

from fastapi import Depends, HTTPException, Request, status, Header
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.security import (
    MIN_LEGACY_INGEST_TOKEN_LENGTH,
    PASSWORD_CHANGE_CLAIM,
    api_key_lookup_prefix,
    decode_access_token,
    hash_ingest_token,
    ingest_token_lookup_prefix,
    is_token_revoked,
    mfa_required_for_admin,
    verify_api_key,
)
from backend import ratelimit

logger = logging.getLogger(__name__)

security_bearer = HTTPBearer(auto_error=False)
agent_key_header = APIKeyHeader(name="X-Phantom-Agent-Key", auto_error=False)

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


def _resolve_user(
    payload: Dict[str, Any],
    db: Session,
    allow_password_change_pending: bool,
    allow_mfa_enrolment_pending: bool = False,
) -> User:
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
    if not allow_mfa_enrolment_pending and mfa_enrolment_required(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Multi-factor authentication is mandatory for administrators: enrol an authenticator first.",
        )
    return user


def mfa_enrolment_required(user: User) -> bool:
    """True when policy require_mfa_for_admin is on and this administrator has not enabled MFA yet."""
    return bool(
        not user.mfa_enabled
        and normalize_role(user.role) in ADMIN_ROLES
        and mfa_required_for_admin()
    )


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
    (used only by /auth/me, so the console can render the change-password screen)."""
    return _resolve_user(payload, db, allow_password_change_pending=True, allow_mfa_enrolment_pending=True)


def get_current_user_for_mfa_enrolment(
    payload: Dict[str, Any] = Depends(get_token_payload),
    db: Session = Depends(get_db),
) -> User:
    """Fully established session that may still be missing mandatory MFA (only the MFA enrolment endpoints use this)."""
    return _resolve_user(payload, db, allow_password_change_pending=False, allow_mfa_enrolment_pending=True)


def require_human_analyst(current_user: User = Depends(get_current_user)) -> User:
    """Authenticated, active, non-service account. Used where a person must make the decision
    (approving containment, deciding on alerts, approving AI agent proposals)."""
    return current_user


def _client_in_allowlist(ip: str, allowlist) -> bool:
    try:
        client = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowlist or []:
        try:
            if client in ipaddress.ip_network(str(entry).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def _audit_service_key(db: Session, level: str, message: str, target: Optional[str], details: Dict[str, Any]) -> None:
    from backend.routers.logs import record_log  # lazy: routers.logs imports this module

    try:
        record_log(db, "AUTH", level, message, target=target, details=details)
    except Exception as exc:  # auditing must not turn a decision into a 500
        db.rollback()
        logger.error(f"Could not record service-account key audit entry: {exc}")


def get_current_service_account(
    request: Request,
    agent_key: Optional[str] = Depends(agent_key_header),
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Authenticate an AI agent / integration by its API key.

    The key is sent as `X-Phantom-Agent-Key: phk_...` (or `Authorization: Bearer phk_...`).
    Operator JWTs are not accepted here, and service-account keys are not accepted by
    get_current_user, so the two APIs cannot be mixed up. Expiry and the source-IP allow-list
    of the account's policy are enforced, and every use (success or failure) is written to system_logs.
    """
    from backend.security_models import ServiceAccountPolicy

    key = (agent_key or "").strip()
    if not key and auth is not None and (auth.credentials or "").startswith("phk_"):
        key = auth.credentials.strip()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent API key required: send 'X-Phantom-Agent-Key: <key>'.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    ip = ratelimit.get_client_ip(request)
    where = {"ip": ip, "method": request.method, "path": request.url.path}

    fail_limit = ratelimit.get_limit("service_key_failures")
    if fail_limit and ratelimit.limiter.count(f"fail:svc:{ip}", fail_limit[1]) >= fail_limit[0]:
        raise ratelimit._too_many(fail_limit[1] // 2)

    lookup = api_key_lookup_prefix(key)
    candidates = (
        db.query(User).filter(User.api_key_prefix == lookup, User.is_service_account.is_(True)).all()
        if lookup else []
    )
    account = next((c for c in candidates if verify_api_key(key, c.api_key_hash)), None)
    if account is None:
        if fail_limit:
            ratelimit.limiter.hit(f"fail:svc:{ip}", fail_limit[1])
        _audit_service_key(db, "WARNING", f"Rejected agent API key ({lookup or 'malformed'}) from {ip}.",
                           lookup, {**where, "outcome": "invalid_key"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not account.is_active:
        _audit_service_key(db, "WARNING", f"Agent API key of disabled service account '{account.username}' used from {ip}.",
                           account.username, {**where, "outcome": "account_disabled"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Service account is disabled.")

    policy = db.query(ServiceAccountPolicy).filter(ServiceAccountPolicy.user_id == account.user_id).first()
    now = datetime.now(timezone.utc)
    if policy is not None:
        expires = _as_utc(policy.expires_at)
        if expires is not None and now >= expires:
            _audit_service_key(db, "WARNING", f"Expired agent API key of '{account.username}' used from {ip}.",
                               account.username, {**where, "outcome": "key_expired"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This agent API key has expired; ask an administrator to rotate it.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        if policy.ip_allowlist and not _client_in_allowlist(ip, policy.ip_allowlist):
            _audit_service_key(db, "WARNING", f"Agent API key of '{account.username}' used from disallowed address {ip}.",
                               account.username, {**where, "outcome": "ip_not_allowed"})
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This API key cannot be used from your address.")
    else:
        policy = ServiceAccountPolicy(user_id=account.user_id)
        db.add(policy)

    policy.last_used_at = now.replace(tzinfo=None)
    policy.last_used_ip = ip[:64]
    db.commit()
    _audit_service_key(db, "INFO", f"Service account '{account.username}' authenticated with its API key from {ip}.",
                       account.username, {**where, "outcome": "ok", "api_key_prefix": account.api_key_prefix})
    return account


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


_warned_short_legacy_token = False


def _legacy_ingest_token() -> str:
    """PHANTOM_INGEST_TOKEN is honoured only when it is long enough to resist guessing."""
    global _warned_short_legacy_token
    legacy = os.getenv("PHANTOM_INGEST_TOKEN", "").strip()
    if legacy and len(legacy) < MIN_LEGACY_INGEST_TOKEN_LENGTH:
        if not _warned_short_legacy_token:
            logger.warning(
                f"PHANTOM_INGEST_TOKEN is ignored because it is shorter than {MIN_LEGACY_INGEST_TOKEN_LENGTH} "
                "characters. Create per-sender tokens (POST /api/ingest-tokens) or use a longer value."
            )
            _warned_short_legacy_token = True
        return ""
    return legacy


def _match_db_ingest_token(db: Session, presented: str):
    from backend.security_models import IngestToken

    lookup = ingest_token_lookup_prefix(presented)
    digest = hash_ingest_token(presented)
    rows = db.query(IngestToken).filter(IngestToken.lookup_prefix == lookup).all() if lookup else []
    now = datetime.now(timezone.utc)
    matched = None
    for row in rows:
        if hmac.compare_digest(digest, row.token_hash or "") and matched is None:
            matched = row
    if not rows:
        hmac.compare_digest(digest, digest[::-1])  # keep timing similar when the prefix is unknown
    if matched is None or matched.revoked_at is not None:
        return None
    expires = _as_utc(matched.expires_at)
    if expires is not None and now >= expires:
        return None
    return matched


def _any_active_ingest_token(db: Session) -> bool:
    from backend.security_models import IngestToken

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return db.query(IngestToken).filter(
        IngestToken.revoked_at.is_(None),
        (IngestToken.expires_at.is_(None)) | (IngestToken.expires_at > now),
    ).first() is not None


def require_ingest_token(
    request: Request,
    x_phantom_ingest_token: Optional[str] = Header(default=None, alias="X-Phantom-Ingest-Token"),
    db: Session = Depends(get_db),
) -> None:
    """Authenticate SIEM / EDR / XDR webhook senders.

    Accepts a per-sender token created with POST /api/ingest-tokens (stored hashed, revocable, with
    last-use tracking), or the legacy shared PHANTOM_INGEST_TOKEN when it is at least 32 characters.
    Ingestion stays disabled (503) until one of them exists, so a fresh install never accepts
    unauthenticated alerts that can trigger containment. Repeated bad tokens from one address are throttled.
    """
    ip = ratelimit.get_client_ip(request)
    fail_limit = ratelimit.get_limit("ingest_failures")
    if fail_limit and ratelimit.limiter.count(f"fail:ingest:{ip}", fail_limit[1]) >= fail_limit[0]:
        raise ratelimit._too_many(fail_limit[1] // 2)

    presented = (x_phantom_ingest_token or "").strip()
    if presented:
        row = _match_db_ingest_token(db, presented)
        if row is not None:
            row.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()
            request.state.ingest_sender = row.name
            return
        legacy = _legacy_ingest_token()
        if legacy and hmac.compare_digest(presented.encode("utf-8"), legacy.encode("utf-8")):
            request.state.ingest_sender = "legacy-shared-token"
            return

    if not (_legacy_ingest_token() or _any_active_ingest_token(db)):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook ingestion is disabled: an administrator must create an ingest token.",
        )
    if fail_limit:
        ratelimit.limiter.hit(f"fail:ingest:{ip}", fail_limit[1])
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid X-Phantom-Ingest-Token header.",
    )
