import ipaddress
import logging
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend import rbac, ratelimit

from backend.database import get_db
from backend.models import SystemLog, User
from backend.schemas import (
    UserResponse,
    UserCreateRequest,
    UserCreateResponse,
    UserUpdateRequest,
    ServiceAccountCreateRequest,
    ServiceAccountKeyResponse,
    ServiceAccountPolicyRequest,
    StepUpBody,
    StepUpConfirmation,
)
from backend.security import hash_password, generate_temporary_password, generate_api_key, verify_password
from backend.dependencies import (
    ADMIN_ROLES,
    ROLE_AI_AGENT,
    ROLE_SOC_ANALYST,
    normalize_role,
    require_admin,
    role_catalog,
)
from backend.routers.auth import get_bootstrap_admin_username, user_public_dict, _totp_ok
from backend.security_models import ServiceAccountPolicy
from backend.routers.logs import get_naive_utc, record_log

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["User Accounts & Access Management (Admin Only)"])


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{2,49}$")
MAX_ALLOWLIST_ENTRIES = 50


def _get_user_or_404(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    return user


def _policy_for(db: Session, user: User) -> Optional[ServiceAccountPolicy]:
    if not user.is_service_account:
        return None
    return db.query(ServiceAccountPolicy).filter(ServiceAccountPolicy.user_id == user.user_id).first()


def _public(user: User, policy: Optional[ServiceAccountPolicy] = None, actions: Optional[dict] = None) -> dict:
    data = {**user_public_dict(user), "api_key_prefix": user.api_key_prefix}
    if actions is not None:
        data["account_actions"] = actions
    if user.is_service_account:
        data.update(
            expires_at=policy.expires_at.isoformat() if policy and policy.expires_at else None,
            ip_allowlist=list(policy.ip_allowlist or []) if policy else [],
            last_used_at=policy.last_used_at.isoformat() if policy and policy.last_used_at else None,
            last_used_ip=policy.last_used_ip if policy else None,
        )
    return data


def _validated_username(username: str, db: Session) -> str:
    username = (username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty.")
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-50 characters: letters, digits, '.', '_', '@', '+' or '-', starting with a letter or digit.",
        )
    if db.query(User).filter(func.lower(User.username) == username.lower()).first():
        raise HTTPException(status_code=400, detail=f"Operator username '{username}' already exists in the system.")
    return username


def _validated_allowlist(entries: Optional[List[str]]) -> Optional[List[str]]:
    """Normalised list of IPs / CIDR networks; None when not supplied, [] to remove the restriction."""
    if entries is None:
        return None
    if len(entries) > MAX_ALLOWLIST_ENTRIES:
        raise HTTPException(status_code=400, detail=f"ip_allowlist can hold at most {MAX_ALLOWLIST_ENTRIES} entries.")
    result: List[str] = []
    for raw in entries:
        try:
            network = ipaddress.ip_network((raw or "").strip(), strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"'{(raw or '')[:60]}' is not an IP address or CIDR network.")
        text = str(network)
        if text not in result:
            result.append(text)
    return result


DEFAULT_AGENT_KEY_DAYS = 90


def default_agent_key_days() -> int:
    """Lifetime in days of a service-account key created without `expires_in_days`
    (PHANTOM_AGENT_KEY_DEFAULT_DAYS, default 90; 0 = such keys never expire)."""
    raw = os.getenv("PHANTOM_AGENT_KEY_DEFAULT_DAYS", "").strip()
    if not raw:
        return DEFAULT_AGENT_KEY_DAYS
    try:
        return min(max(int(raw), 0), 3650)
    except ValueError:
        logger.warning("Invalid PHANTOM_AGENT_KEY_DEFAULT_DAYS=%r; using %d.", raw, DEFAULT_AGENT_KEY_DAYS)
        return DEFAULT_AGENT_KEY_DAYS


def _expiry_from_days(days: Optional[int]) -> Optional[datetime]:
    if days is None:
        return None
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(tzinfo=None)


def _unique_api_key(db: Session):
    """(plaintext key, prefix, digest) whose lookup prefix is not used by any account yet."""
    for _ in range(20):
        key, prefix, digest = generate_api_key()
        if not db.query(User).filter(User.api_key_prefix == prefix).first():
            return key, prefix, digest
    raise HTTPException(status_code=500, detail="Could not allocate a unique API key id; try again.")


# --- Account-management policy enforcement -------------------------------------------------------------------
# The rules live in backend/rbac.py (pure functions). Everything here is the plumbing that makes them hold:
#  * every privileged account change runs under one lock and re-reads the acting administrator and the target
#    from the database inside it, so two administrators demoting each other at the same moment cannot both win
#    (the loser finds their own admin rights gone) and the "last active administrator" count is never stale;
#  * a sensitive change needs the acting admin's own password (and a fresh TOTP code when they use MFA);
#  * the change and its audit entry are committed together; refusals are audited too (never silently dropped).
_ACCOUNT_CHANGE_LOCK = threading.RLock()  # in-process; row locks (SELECT ... FOR UPDATE) cover several workers on Postgres


def _subject(user: User) -> rbac.Subject:
    return rbac.Subject(
        user_id=user.user_id,
        username=user.username,
        role=user.role or "",
        is_active=bool(user.is_active),
        is_service_account=bool(user.is_service_account),
        is_bootstrap=user.username == get_bootstrap_admin_username(),
    )


def _is_active_human_admin(user: User) -> bool:
    return bool(user.is_active) and not user.is_service_account and normalize_role(user.role) in ADMIN_ROLES


def _other_active_admins(db: Session, target: Optional[User]) -> int:
    """Active human administrators other than `target` (the acting administrator counts)."""
    excluded = target.user_id if target is not None else None
    return sum(
        1 for u in db.query(User).filter(User.is_active.is_(True), User.is_service_account.is_(False)).all()
        if u.user_id != excluded and normalize_role(u.role) in ADMIN_ROLES
    )


def _active_admin_count(db: Session, excluding_user_id: int = None) -> int:
    """Kept for callers outside this module: active human administrators, optionally leaving one account out."""
    return sum(
        1 for u in db.query(User).filter(User.is_active.is_(True)).all()
        if u.user_id != excluding_user_id and _is_active_human_admin(u)
    )


def _audit(db: Session, level: str, message: str, target: Optional[str], details: Dict[str, Any], commit: bool = True) -> None:
    """Add an RBAC audit entry; commit=False lets the caller commit it together with the change it describes."""
    db.add(SystemLog(source="RBAC", level=level.upper(), message=message,
                     target=target[:200] if target else target, details=details, created_at=get_naive_utc()))
    if commit:
        db.commit()


def _refuse(db: Session, status_code: int, code: str, message: str, *, actor: str, target: Optional[str],
            action: str, ip: str, attempted: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
    """Roll back, audit the rejected attempt (who, what, why) and answer with {"message", "code"}."""
    db.rollback()
    _audit(db, "WARNING", f"DENIED: admin '{actor}' tried to {action} on '{target or '-'}': {message}", target,
           {"outcome": "denied", "code": code, "by": actor, "action": action, "ip": ip, "attempted": attempted or {}})
    raise HTTPException(status_code=status_code, detail={"message": message, "code": code}, headers=headers)


def _refuse_unknown_fields(db: Session, admin: User, extra: Optional[Dict[str, Any]], allowed, target: Optional[str],
                           action: str, ip: str) -> None:
    """Mass-assignment protection: a body field that is not whitelisted is refused and audited, never bound."""
    names = rbac.unknown_fields(extra, allowed)
    if names:
        _refuse(db, 422, "fields_not_allowed",
                f"These fields cannot be set through this endpoint: {', '.join(names)}.",
                actor=admin.username, target=target, action=action, ip=ip, attempted={"fields": names})


class _StepUpThrottled(Exception):
    def __init__(self, retry_after: int):
        super().__init__("step-up throttled")
        self.retry_after = retry_after


def _verify_step_up(db: Session, actor: User, confirmation: Optional[StepUpConfirmation], ip: str) -> bool:
    """True when the acting admin proves who they are: own password, plus a fresh TOTP code with MFA.

    Wrong confirmations are counted in their own step-up counters (never the sign-in ones, so they cannot slow down
    or block the admin's real logins); `_StepUpThrottled` carries the real remaining lock time."""
    if confirmation is None:
        return False
    wait = ratelimit.stepup_retry_after(actor.username, ip)
    if wait:
        raise _StepUpThrottled(wait)
    ok = bool(verify_password(confirmation.current_password, actor.password_hash))
    if ok and actor.mfa_enabled:
        ok = _totp_ok(db, actor, confirmation.mfa_code)
    if ok:
        ratelimit.stepup_clear(actor.username, ip)
    else:
        ratelimit.stepup_register_failure(actor.username, ip)
    return ok


def _enforce(db: Session, request: Request, actor: User, target: Optional[User], decision: rbac.Decision,
             confirmation: Optional[StepUpConfirmation], *, action: str, attempted: Optional[Dict[str, Any]] = None) -> bool:
    """Apply a policy decision. Returns True when a step-up was verified; raises otherwise when refused."""
    ip = ratelimit.get_client_ip(request)
    actor_name = actor.username
    target_name = target.username if target is not None else None
    common = dict(actor=actor_name, target=target_name, action=action, ip=ip, attempted=attempted)

    if not decision.allowed:
        forbidden = decision.code in ("actor_not_admin", "service_account_cannot_manage")
        _refuse(db, status.HTTP_403_FORBIDDEN if forbidden else status.HTTP_400_BAD_REQUEST,
                decision.code, decision.message, **common)
    if not (decision.step_up or confirmation is not None):
        return False
    if confirmation is None:
        _refuse(db, status.HTTP_428_PRECONDITION_REQUIRED, "step_up_required",
                f"{decision.reason or 'This change'} Confirm with your own password"
                f"{' and a current MFA code' if actor.mfa_enabled else ''} to continue.", **common)
    try:
        verified = _verify_step_up(db, actor, confirmation, ip)
    except _StepUpThrottled as throttled:
        _refuse(db, status.HTTP_429_TOO_MANY_REQUESTS, "step_up_throttled",
                f"Too many failed confirmations. Try again in about {max(1, -(-throttled.retry_after // 60))} minute(s).",
                headers={"Retry-After": str(throttled.retry_after)}, **common)
    if not verified:
        _refuse(db, status.HTTP_403_FORBIDDEN, "step_up_failed",
                "Confirmation failed: your own password"
                f"{' and a current MFA code' if actor.mfa_enabled else ''} did not match. Nothing was changed.", **common)
    return True


@contextmanager
def _account_change(db: Session, admin: User, request: Request, action: str, target_id: Optional[int] = None):
    """Serialise a privileged account change and hand back the acting admin and the target as stored NOW.

    The target (when given) is 404 if missing. The acting administrator is re-read under the lock: an admin whose
    rights were removed a moment ago by someone else gets 403 and changes nothing.
    """
    with _ACCOUNT_CHANGE_LOCK:
        try:
            criteria = User.is_service_account.is_(False)
            if target_id is not None:
                criteria = or_(criteria, User.user_id == target_id)
            rows = (db.query(User).filter(criteria).order_by(User.user_id.asc())
                    .with_for_update().populate_existing().all())  # row locks on Postgres; ignored by SQLite
            by_id = {u.user_id: u for u in rows}
            actor = by_id.get(admin.user_id)
            if actor is None or rbac.actor_denial(_subject(actor)) is not None:
                _refuse(db, status.HTTP_403_FORBIDDEN, "admin_rights_revoked",
                        "Your administrator access was removed or your account was disabled; nothing was changed.",
                        actor=admin.username, target=None, action=action, ip=ratelimit.get_client_ip(request))
            target = None
            if target_id is not None:
                target = by_id.get(target_id)
                if target is None:
                    raise HTTPException(status_code=404, detail="User account not found.")
            yield actor, target
        except BaseException:
            db.rollback()
            raise


def _policy_error(db: Session, request: Request, admin: User, violation: rbac.PolicyViolation, action: str,
                  target: Optional[str], attempted: Optional[Dict[str, Any]] = None):
    _refuse(db, status.HTTP_400_BAD_REQUEST, violation.code, violation.message, actor=admin.username, target=target,
            action=action, ip=ratelimit.get_client_ip(request), attempted=attempted)


def _change_level(*subjects: rbac.Subject, grants_admin: bool = False) -> str:
    """Audit level of an account change: WARNING when an administrator account is involved or admin is granted."""
    return "WARNING" if grants_admin or any(s.is_admin for s in subjects) else "ACTION"


@router.get("/roles")
def list_roles(admin: User = Depends(require_admin)):
    """[Admin Only] Canonical roles and their access level."""
    return role_catalog()


@router.get("", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] List operator and service accounts. Password hashes and MFA secrets are never returned.
    Each row carries `account_actions`: what the signed-in administrator may do to it (backend/rbac.py)."""
    users = db.query(User).order_by(User.user_id.asc()).all()
    policies: Dict[int, ServiceAccountPolicy] = {p.user_id: p for p in db.query(ServiceAccountPolicy).all()}
    actor = _subject(admin)
    total_admins = sum(1 for u in users if _is_active_human_admin(u))
    result = []
    for u in users:
        others = total_admins - (1 if _is_active_human_admin(u) else 0)
        result.append(_public(u, policies.get(u.user_id), rbac.row_permissions(actor, _subject(u), others)))
    return result


@router.post("", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Provision an operator account. A random one-time password is generated and
    returned once in `temporary_password`; the operator must change it at first sign-in.
    Only the named roles can be assigned; the AI-agent role is refused. Granting the Admin role is audit-logged at
    WARNING level.
    """
    ip = ratelimit.get_client_ip(request)
    _refuse_unknown_fields(db, admin, payload.model_extra, rbac.CREATABLE_FIELDS, None, "create account", ip)
    with _account_change(db, admin, request, "create account") as (actor, _):
        try:
            role = rbac.validate_assignable_role(payload.role or ROLE_SOC_ANALYST)
        except rbac.PolicyViolation as violation:
            _policy_error(db, request, actor, violation, "create account", payload.username[:50], {"role": payload.role})
        username = _validated_username(payload.username, db)
        decision = rbac.decide(rbac.Action.CREATE_USER, _subject(actor), new_role=role)
        stepped_up = _enforce(db, request, actor, None, decision, payload.confirmation, action="create account",
                              attempted={"username": username, "role": role})
        temporary_password = generate_temporary_password()
        now = datetime.now(timezone.utc)
        new_user = User(
            username=username,
            password_hash=hash_password(temporary_password),
            role=role,
            must_change_password=True,
            is_active=True,
            mfa_enabled=False,  # MFA is enrolled by the operator via /auth/mfa/setup
            password_changed_at=now,
            created_at=now
        )
        db.add(new_user)
        grants_admin = normalize_role(role) in ADMIN_ROLES
        _audit(db, "WARNING" if grants_admin else "ACTION",
               f"Admin '{actor.username}' provisioned account '{username}' with role '{role}'."
               + (" Administrator role granted." if grants_admin else ""),
               username, {"role": role, "by": actor.username, "grants_admin": grants_admin, "step_up": stepped_up,
                          "ip": ip}, commit=False)
        db.commit()
        db.refresh(new_user)

    return {**_public(new_user), "temporary_password": temporary_password}


@router.post("/service-accounts", response_model=ServiceAccountKeyResponse, status_code=status.HTTP_201_CREATED)
def create_service_account(
    payload: ServiceAccountCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Create a service account for an AI agent or integration. The API key is returned
    once in `api_key`; it authenticates with `X-Phantom-Agent-Key`. Service accounts cannot sign in
    to the console and cannot call operator endpoints. Their role is always 'AI Agent' (never an
    administrator) and cannot be set here.
    """
    ip = ratelimit.get_client_ip(request)
    _refuse_unknown_fields(db, admin, payload.model_extra, rbac.SERVICE_CREATABLE_FIELDS, None, "create service account", ip)
    with _account_change(db, admin, request, "create service account") as (actor, _):
        username = _validated_username(payload.username, db)
        allowlist = _validated_allowlist(payload.ip_allowlist)
        decision = rbac.decide(rbac.Action.CREATE_SERVICE_ACCOUNT, _subject(actor))
        _enforce(db, request, actor, None, decision, None, action="create service account", attempted={"username": username})
        api_key, prefix, digest = _unique_api_key(db)
        now = datetime.now(timezone.utc)
        account = User(
            username=username,
            password_hash=hash_password(generate_temporary_password()),  # never disclosed; password sign-in is refused
            role=ROLE_AI_AGENT,
            must_change_password=False,
            is_active=True,
            mfa_enabled=False,
            is_service_account=True,
            api_key_hash=digest,
            api_key_prefix=prefix,
            password_changed_at=now,
            created_at=now,
        )
        db.add(account)
        db.flush()
        policy = ServiceAccountPolicy(
            user_id=account.user_id,
            # An explicit value always wins; an omitted one gets the default lifetime so no key lives forever by accident.
            expires_at=_expiry_from_days(
                payload.expires_in_days if payload.expires_in_days is not None else (default_agent_key_days() or None)),
            ip_allowlist=allowlist or [],
        )
        db.add(policy)
        _audit(db, "ACTION", f"Admin '{actor.username}' created service account '{username}' (key {prefix}).", username,
               {"api_key_prefix": prefix, "by": actor.username, "role": ROLE_AI_AGENT,
                "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                "ip_allowlist": policy.ip_allowlist, "ip": ip}, commit=False)
        db.commit()
        db.refresh(account)
        db.refresh(policy)
    return {**_public(account, policy), "api_key": api_key}


def _apply_policy(db: Session, account: User, change: ServiceAccountPolicyRequest) -> ServiceAccountPolicy:
    policy = _policy_for(db, account)
    if policy is None:
        policy = ServiceAccountPolicy(user_id=account.user_id, ip_allowlist=[])
        db.add(policy)
    if change.clear_expiry:
        policy.expires_at = None
    elif change.expires_in_days is not None:
        policy.expires_at = _expiry_from_days(change.expires_in_days)
    allowlist = _validated_allowlist(change.ip_allowlist)
    if allowlist is not None:
        policy.ip_allowlist = allowlist
    return policy


@router.post("/{user_id}/rotate-api-key", response_model=ServiceAccountKeyResponse)
def rotate_service_account_key(
    user_id: int,
    request: Request,
    change: Optional[ServiceAccountPolicyRequest] = Body(default=None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Issue a new API key for a service account; the previous key stops working immediately.
    The optional body sets a new expiry (`expires_in_days` / `clear_expiry`) and source allow-list."""
    with _account_change(db, admin, request, "rotate API key", user_id) as (actor, account):
        _enforce(db, request, actor, account,
                 rbac.decide(rbac.Action.ROTATE_KEY, _subject(actor), _subject(account)), None, action="rotate API key")
        existing = _policy_for(db, account)
        if existing and existing.expires_at and (existing.expires_at if existing.expires_at.tzinfo else existing.expires_at.replace(tzinfo=timezone.utc)) <= datetime.now(timezone.utc) \
                and not (change and (change.clear_expiry or change.expires_in_days is not None)):
            raise HTTPException(status_code=400, detail="The previous key has expired: set expires_in_days (or clear_expiry) when rotating.")
        old_prefix = account.api_key_prefix
        api_key, prefix, digest = _unique_api_key(db)
        account.api_key_hash = digest
        account.api_key_prefix = prefix
        policy = _apply_policy(db, account, change or ServiceAccountPolicyRequest())
        _audit(db, "ACTION", f"Admin '{actor.username}' rotated the API key of '{account.username}'.", account.username,
               {"old_prefix": old_prefix, "new_prefix": prefix, "by": actor.username,
                "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                "ip_allowlist": policy.ip_allowlist, "ip": ratelimit.get_client_ip(request)}, commit=False)
        db.commit()
        db.refresh(account)
        db.refresh(policy)
    return {**_public(account, policy), "api_key": api_key}


@router.put("/{user_id}/service-policy", response_model=UserResponse)
def update_service_account_policy(
    user_id: int,
    change: ServiceAccountPolicyRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Change a service account's key expiry and source-address allow-list without rotating the key."""
    with _account_change(db, admin, request, "change key policy", user_id) as (actor, account):
        _enforce(db, request, actor, account,
                 rbac.decide(rbac.Action.SERVICE_POLICY, _subject(actor), _subject(account)), None, action="change key policy")
        policy = _apply_policy(db, account, change)
        _audit(db, "ACTION", f"Admin '{actor.username}' changed the key policy of '{account.username}'.", account.username,
               {"by": actor.username, "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                "ip_allowlist": policy.ip_allowlist, "ip": ratelimit.get_client_ip(request)}, commit=False)
        db.commit()
        db.refresh(policy)
    return _public(account, policy)


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Update role, activation status, or the compromised flag of an account.

    Only those three fields (plus the optional `confirmation`) are accepted; any other field is refused and audited.
    You cannot change your own role or disable yourself, the bootstrap and the last active administrator keep their
    access, service accounts keep their fixed role, and a change to another administrator (or a grant of the Admin role)
    needs `confirmation`: your own password, plus a current MFA code if you use MFA.
    """
    ip = ratelimit.get_client_ip(request)
    _refuse_unknown_fields(db, admin, payload.model_extra, rbac.UPDATABLE_FIELDS, f"#{user_id}", "update account", ip)
    with _account_change(db, admin, request, "update account", user_id) as (actor, user):
        attempted = {k: v for k, v in (("role", payload.role), ("is_active", payload.is_active),
                                       ("compromised_reset_required", payload.compromised_reset_required)) if v is not None}
        new_role = None
        if payload.role is not None and (user.is_service_account or not rbac.role_unchanged(user.role, payload.role)):
            try:
                new_role = rbac.validate_assignable_role(payload.role)
            except rbac.PolicyViolation as violation:
                _policy_error(db, request, actor, violation, "update account", user.username, attempted)
        new_flag = None
        if payload.compromised_reset_required is not None and bool(payload.compromised_reset_required) != bool(user.compromised_reset_required):
            new_flag = payload.compromised_reset_required

        before, target_subject = _subject(user), _subject(user)
        decision = rbac.decide_update(_subject(actor), target_subject, new_role=new_role, new_is_active=payload.is_active,
                                      new_compromised=new_flag, other_active_admins=_other_active_admins(db, user))
        stepped_up = _enforce(db, request, actor, user, decision, payload.confirmation, action="update account",
                              attempted=attempted)

        changes: Dict[str, Any] = {}
        if new_role is not None and new_role != user.role:
            changes["role"] = {"from": user.role, "to": new_role}
            user.role = new_role
        if payload.is_active is not None and payload.is_active != user.is_active:
            changes["is_active"] = {"from": bool(user.is_active), "to": bool(payload.is_active)}
            user.is_active = payload.is_active
        if new_flag is not None:
            changes["compromised_reset_required"] = {"from": bool(user.compromised_reset_required), "to": bool(new_flag)}
            user.compromised_reset_required = new_flag
            if new_flag:
                user.must_change_password = True

        if changes:
            grants_admin = "role" in changes and normalize_role(changes["role"]["to"]) in ADMIN_ROLES and not before.is_admin
            _audit(db, _change_level(before, grants_admin=grants_admin),
                   f"Admin '{actor.username}' updated account '{user.username}'.", user.username,
                   {"changes": changes, "by": actor.username, "target_was_admin": before.is_admin,
                    "grants_admin": grants_admin, "step_up": stepped_up, "ip": ip}, commit=False)
        db.commit()
        db.refresh(user)
    return _public(user, _policy_for(db, user))


@router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    request: Request,
    body: Optional[StepUpBody] = Body(default=None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Replace an operator's password with a random one-time password (returned once),
    sign out their existing sessions, and require a change at next sign-in. Not available for your own account
    (use change-password) or for service accounts. Resetting another administrator needs `confirmation`.
    """
    ip = ratelimit.get_client_ip(request)
    with _account_change(db, admin, request, "reset password", user_id) as (actor, user):
        was_admin = _subject(user).is_admin
        decision = rbac.decide(rbac.Action.RESET_PASSWORD, _subject(actor), _subject(user))
        stepped_up = _enforce(db, request, actor, user, decision, body.confirmation if body else None, action="reset password")

        temporary_password = generate_temporary_password()
        user.password_hash = hash_password(temporary_password)
        user.must_change_password = True
        user.compromised_reset_required = False
        user.failed_login_attempts = 0
        user.locked_until = None
        user.password_changed_at = datetime.now(timezone.utc)
        _audit(db, "WARNING" if was_admin else "ACTION",
               f"Admin '{actor.username}' reset the password of '{user.username}'.", user.username,
               {"by": actor.username, "target_was_admin": was_admin, "step_up": stepped_up, "ip": ip}, commit=False)
        db.commit()
        username = user.username
    ratelimit.clear_username(username)

    return {
        "status": "Success",
        "message": f"Password for operator '{username}' was reset to a one-time password. Existing sessions were signed out and the operator must change it at next sign-in.",
        "temporary_password": temporary_password,
    }


@router.post("/{user_id}/unlock")
def unlock_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Clear a brute-force lockout (people only; service accounts have no password to lock)."""
    with _account_change(db, admin, request, "unlock account", user_id) as (actor, user):
        _enforce(db, request, actor, user, rbac.decide(rbac.Action.UNLOCK, _subject(actor), _subject(user)), None,
                 action="unlock account")
        user.failed_login_attempts = 0
        user.locked_until = None
        _audit(db, "ACTION", f"Admin '{actor.username}' unlocked account '{user.username}'.", user.username,
               {"by": actor.username, "ip": ratelimit.get_client_ip(request)}, commit=False)
        db.commit()
        username = user.username
    ratelimit.clear_username(username)
    return {"status": "Success", "message": f"Account '{username}' unlocked."}


@router.post("/{user_id}/flag-compromised")
def flag_account_compromised(
    user_id: int,
    request: Request,
    body: Optional[StepUpBody] = Body(default=None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] NIST SP 800-63B: flag an account as suspected compromised. Its sessions stop
    working until the operator signs in and changes the password. Not available for your own account or
    for service accounts (rotate the key); flagging another administrator needs `confirmation`.
    """
    ip = ratelimit.get_client_ip(request)
    with _account_change(db, admin, request, "flag account as compromised", user_id) as (actor, user):
        was_admin = _subject(user).is_admin
        decision = rbac.decide(rbac.Action.SET_COMPROMISED, _subject(actor), _subject(user), new_compromised=True)
        stepped_up = _enforce(db, request, actor, user, decision, body.confirmation if body else None,
                              action="flag account as compromised")
        user.compromised_reset_required = True
        user.must_change_password = True
        _audit(db, "WARNING", f"Admin '{actor.username}' flagged '{user.username}' as suspected compromised.", user.username,
               {"by": actor.username, "target_was_admin": was_admin, "step_up": stepped_up, "ip": ip}, commit=False)
        db.commit()
        username = user.username

    return {
        "status": "Success",
        "message": f"Account '{username}' has been marked as compromised. User will be forced to change credentials upon next login.",
        "compromised_reset_required": True
    }


def _delete_account(user_id: int, request: Request, body: Optional[StepUpBody], db: Session, admin: User) -> dict:
    ip = ratelimit.get_client_ip(request)
    with _account_change(db, admin, request, "delete account", user_id) as (actor, user):
        was_admin = _subject(user).is_admin
        decision = rbac.decide(rbac.Action.DELETE, _subject(actor), _subject(user),
                               other_active_admins=_other_active_admins(db, user))
        stepped_up = _enforce(db, request, actor, user, decision, body.confirmation if body else None, action="delete account")

        username = user.username
        was_service = bool(user.is_service_account)
        db.query(ServiceAccountPolicy).filter(ServiceAccountPolicy.user_id == user.user_id).delete(synchronize_session=False)
        db.delete(user)
        _audit(db, "WARNING" if was_admin else "ACTION", f"Admin '{actor.username}' deleted account '{username}'.", username,
               {"by": actor.username, "target_was_admin": was_admin, "service_account": was_service,
                "step_up": stepped_up, "ip": ip}, commit=False)
        db.commit()
    ratelimit.clear_username(username)

    return {
        "status": "Success",
        "message": f"Operator account '{username}' has been removed from the platform."
    }


@router.post("/{user_id}/delete")
def delete_user_post(
    user_id: int,
    request: Request,
    body: Optional[StepUpBody] = Body(default=None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Same as DELETE /users/{id}, for clients and proxies that drop a request body on DELETE.
    The step-up `confirmation` travels in the POST body (the console uses this route)."""
    return _delete_account(user_id, request, body, db, admin)


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    body: Optional[StepUpBody] = Body(default=None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Delete an account. You cannot delete yourself, the bootstrap admin, or the last active admin.
    Deleting an administrator is audit-logged at WARNING level and needs `confirmation` (your own password, plus a
    current MFA code with MFA). A request body on DELETE is dropped by some proxies; use POST /users/{id}/delete then."""
    return _delete_account(user_id, request, body, db, admin)
