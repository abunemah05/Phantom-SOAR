import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend import ratelimit

from backend.database import get_db
from backend.models import User
from backend.schemas import (
    UserResponse,
    UserCreateRequest,
    UserCreateResponse,
    UserUpdateRequest,
    ServiceAccountCreateRequest,
    ServiceAccountKeyResponse,
    ServiceAccountPolicyRequest,
)
from backend.security import hash_password, generate_temporary_password, generate_api_key
from backend.dependencies import (
    ADMIN_ROLES,
    ROLE_AI_AGENT,
    ROLE_SOC_ANALYST,
    SERVICE_ROLES,
    is_known_role,
    normalize_role,
    require_admin,
    role_catalog,
)
from backend.routers.auth import get_bootstrap_admin_username, user_public_dict
from backend.security_models import ServiceAccountPolicy
from backend.routers.logs import record_log

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


def _public(user: User, policy: Optional[ServiceAccountPolicy] = None) -> dict:
    data = {**user_public_dict(user), "api_key_prefix": user.api_key_prefix}
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


def _validated_role(role: str) -> str:
    role = " ".join((role or "").split())
    if not role:
        raise HTTPException(status_code=400, detail="Role cannot be empty.")
    if not is_known_role(role) or normalize_role(role) in SERVICE_ROLES:
        allowed = ", ".join(r["role"] for r in role_catalog())
        raise HTTPException(status_code=400, detail=f"Unknown role '{role}'. Assign one of: {allowed}.")
    return role


def _active_admin_count(db: Session, excluding_user_id: int = None) -> int:
    count = 0
    for u in db.query(User).filter(User.is_active.is_(True)).all():
        if u.user_id == excluding_user_id or u.is_service_account:
            continue
        if normalize_role(u.role) in ADMIN_ROLES:
            count += 1
    return count


@router.get("/roles")
def list_roles(admin: User = Depends(require_admin)):
    """[Admin Only] Canonical roles and their access level."""
    return role_catalog()


@router.get("", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] List operator and service accounts. Password hashes and MFA secrets are never returned."""
    users = db.query(User).order_by(User.user_id.asc()).all()
    policies: Dict[int, ServiceAccountPolicy] = {p.user_id: p for p in db.query(ServiceAccountPolicy).all()}
    return [_public(u, policies.get(u.user_id)) for u in users]


@router.post("", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Provision an operator account. A random one-time password is generated and
    returned once in `temporary_password`; the operator must change it at first sign-in.
    """
    username = _validated_username(payload.username, db)
    role = _validated_role(payload.role or ROLE_SOC_ANALYST)
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
    db.commit()
    db.refresh(new_user)

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' provisioned account '{username}' with role '{role}'.",
               target=username, details={"role": role, "by": admin.username})

    return {**_public(new_user), "temporary_password": temporary_password}


@router.post("/service-accounts", response_model=ServiceAccountKeyResponse, status_code=status.HTTP_201_CREATED)
def create_service_account(
    payload: ServiceAccountCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Create a service account for an AI agent or integration. The API key is returned
    once in `api_key`; it authenticates with `X-Phantom-Agent-Key`. Service accounts cannot sign in
    to the console and cannot call operator endpoints.
    """
    username = _validated_username(payload.username, db)
    allowlist = _validated_allowlist(payload.ip_allowlist)
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
        expires_at=_expiry_from_days(payload.expires_in_days),
        ip_allowlist=allowlist or [],
    )
    db.add(policy)
    db.commit()
    db.refresh(account)
    db.refresh(policy)

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' created service account '{username}' (key {prefix}).",
               target=username, details={"api_key_prefix": prefix, "by": admin.username,
                                         "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                                         "ip_allowlist": policy.ip_allowlist})
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
    change: Optional[ServiceAccountPolicyRequest] = Body(default=None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Issue a new API key for a service account; the previous key stops working immediately.
    The optional body sets a new expiry (`expires_in_days` / `clear_expiry`) and source allow-list."""
    account = _get_user_or_404(db, user_id)
    if not account.is_service_account:
        raise HTTPException(status_code=400, detail="Only service accounts have API keys.")
    existing = _policy_for(db, account)
    if existing and existing.expires_at and existing.expires_at <= datetime.now(timezone.utc).replace(tzinfo=None) \
            and not (change and (change.clear_expiry or change.expires_in_days is not None)):
        raise HTTPException(status_code=400, detail="The previous key has expired: set expires_in_days (or clear_expiry) when rotating.")
    old_prefix = account.api_key_prefix
    api_key, prefix, digest = _unique_api_key(db)
    account.api_key_hash = digest
    account.api_key_prefix = prefix
    policy = _apply_policy(db, account, change or ServiceAccountPolicyRequest())
    db.commit()
    db.refresh(account)
    db.refresh(policy)

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' rotated the API key of '{account.username}'.",
               target=account.username, details={"old_prefix": old_prefix, "new_prefix": prefix, "by": admin.username,
                                                 "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                                                 "ip_allowlist": policy.ip_allowlist})
    return {**_public(account, policy), "api_key": api_key}


@router.put("/{user_id}/service-policy", response_model=UserResponse)
def update_service_account_policy(
    user_id: int,
    change: ServiceAccountPolicyRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Change a service account's key expiry and source-address allow-list without rotating the key."""
    account = _get_user_or_404(db, user_id)
    if not account.is_service_account:
        raise HTTPException(status_code=400, detail="Only service accounts have an API key policy.")
    policy = _apply_policy(db, account, change)
    db.commit()
    db.refresh(policy)
    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' changed the key policy of '{account.username}'.",
               target=account.username, details={"by": admin.username,
                                                 "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                                                 "ip_allowlist": policy.ip_allowlist})
    return _public(account, policy)


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Update role, activation status, or the compromised flag of an account."""
    user = _get_user_or_404(db, user_id)
    changes = {}

    if payload.role is not None and user.is_service_account:
        raise HTTPException(status_code=400, detail="Service account roles are fixed; create a separate account instead.")
    new_role = _validated_role(payload.role) if payload.role is not None else None
    deactivating = payload.is_active is False and user.is_active
    demoting = (
        new_role is not None
        and normalize_role(user.role) in ADMIN_ROLES
        and normalize_role(new_role) not in ADMIN_ROLES
    )

    if deactivating and user.user_id == admin.user_id:
        raise HTTPException(status_code=400, detail="You cannot disable your own account.")
    bootstrap = get_bootstrap_admin_username()
    if deactivating and user.username == bootstrap:
        raise HTTPException(status_code=400, detail=f"Cannot disable the bootstrap administrator account '{bootstrap}'.")
    if (deactivating or demoting) and user.is_active and normalize_role(user.role) in ADMIN_ROLES \
            and _active_admin_count(db, excluding_user_id=user.user_id) == 0:
        raise HTTPException(status_code=400, detail="This change would leave the platform without an active administrator.")

    if new_role is not None and new_role != user.role:
        changes["role"] = {"from": user.role, "to": new_role}
        user.role = new_role

    if payload.is_active is not None and payload.is_active != user.is_active:
        changes["is_active"] = payload.is_active
        user.is_active = payload.is_active

    if payload.compromised_reset_required is not None:
        changes["compromised_reset_required"] = payload.compromised_reset_required
        user.compromised_reset_required = payload.compromised_reset_required
        if payload.compromised_reset_required:
            user.must_change_password = True

    db.commit()
    db.refresh(user)

    if changes:
        record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' updated account '{user.username}'.",
                   target=user.username, details={"changes": changes, "by": admin.username})
    return _public(user, _policy_for(db, user))


@router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Replace an operator's password with a random one-time password (returned once),
    sign out their existing sessions, and require a change at next sign-in.
    """
    user = _get_user_or_404(db, user_id)
    if user.is_service_account:
        raise HTTPException(status_code=400, detail="Service accounts do not use passwords; rotate their API key instead.")

    temporary_password = generate_temporary_password()
    user.password_hash = hash_password(temporary_password)
    user.must_change_password = True
    user.compromised_reset_required = False
    user.failed_login_attempts = 0
    user.locked_until = None
    user.password_changed_at = datetime.now(timezone.utc)
    db.commit()
    ratelimit.clear_username(user.username)

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' reset the password of '{user.username}'.",
               target=user.username, details={"by": admin.username})

    return {
        "status": "Success",
        "message": f"Password for operator '{user.username}' was reset to a one-time password. Existing sessions were signed out and the operator must change it at next sign-in.",
        "temporary_password": temporary_password,
    }


@router.post("/{user_id}/unlock")
def unlock_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Clear a brute-force lockout."""
    user = _get_user_or_404(db, user_id)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    ratelimit.clear_username(user.username)
    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' unlocked account '{user.username}'.",
               target=user.username, details={"by": admin.username})
    return {"status": "Success", "message": f"Account '{user.username}' unlocked."}


@router.post("/{user_id}/flag-compromised")
def flag_account_compromised(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] NIST SP 800-63B: flag an account as suspected compromised. Its sessions stop
    working until the operator signs in and changes the password.
    """
    user = _get_user_or_404(db, user_id)
    if user.user_id == admin.user_id:
        raise HTTPException(status_code=400, detail="Change your own password instead of flagging your own account.")

    user.compromised_reset_required = True
    user.must_change_password = True
    db.commit()

    record_log(db, "RBAC", "WARNING", f"Admin '{admin.username}' flagged '{user.username}' as suspected compromised.",
               target=user.username, details={"by": admin.username})

    return {
        "status": "Success",
        "message": f"Account '{user.username}' has been marked as compromised. User will be forced to change credentials upon next login.",
        "compromised_reset_required": True
    }


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Delete an account. You cannot delete yourself, the bootstrap admin, or the last active admin."""
    user = _get_user_or_404(db, user_id)

    if user.user_id == admin.user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    bootstrap = get_bootstrap_admin_username()
    if user.username == bootstrap:
        raise HTTPException(status_code=400, detail=f"Bootstrap administrator account '{bootstrap}' cannot be deleted.")
    if user.is_active and normalize_role(user.role) in ADMIN_ROLES and _active_admin_count(db, excluding_user_id=user.user_id) == 0:
        raise HTTPException(status_code=400, detail="Cannot delete the last active administrator.")

    username = user.username
    db.query(ServiceAccountPolicy).filter(ServiceAccountPolicy.user_id == user.user_id).delete(synchronize_session=False)
    db.delete(user)
    db.commit()
    ratelimit.clear_username(username)

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' deleted account '{username}'.",
               target=username, details={"by": admin.username})

    return {
        "status": "Success",
        "message": f"Operator account '{username}' has been removed from the platform."
    }
