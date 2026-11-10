import logging
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.schemas import (
    UserResponse,
    UserCreateRequest,
    UserCreateResponse,
    UserUpdateRequest,
    ServiceAccountCreateRequest,
    ServiceAccountKeyResponse,
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
from backend.routers.auth import BOOTSTRAP_ADMIN_USERNAME
from backend.routers.logs import record_log

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["User Accounts & Access Management (Admin Only)"])


def _get_user_or_404(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    return user


def _public(user: User) -> dict:
    return {**user.to_dict(), "api_key_prefix": user.api_key_prefix}


def _validated_username(username: str, db: Session) -> str:
    username = (username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty.")
    if len(username) > 50:
        raise HTTPException(status_code=400, detail="Username cannot exceed 50 characters.")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail=f"Operator username '{username}' already exists in the system.")
    return username


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
    return [_public(u) for u in users]


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
    api_key, prefix, digest = generate_api_key()
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
    db.commit()
    db.refresh(account)

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' created service account '{username}' (key {prefix}).",
               target=username, details={"api_key_prefix": prefix, "by": admin.username})
    return {**_public(account), "api_key": api_key}


@router.post("/{user_id}/rotate-api-key", response_model=ServiceAccountKeyResponse)
def rotate_service_account_key(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Issue a new API key for a service account; the previous key stops working immediately."""
    account = _get_user_or_404(db, user_id)
    if not account.is_service_account:
        raise HTTPException(status_code=400, detail="Only service accounts have API keys.")
    old_prefix = account.api_key_prefix
    api_key, prefix, digest = generate_api_key()
    account.api_key_hash = digest
    account.api_key_prefix = prefix
    db.commit()
    db.refresh(account)

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' rotated the API key of '{account.username}'.",
               target=account.username, details={"old_prefix": old_prefix, "new_prefix": prefix, "by": admin.username})
    return {**_public(account), "api_key": api_key}


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
    if deactivating and user.username == BOOTSTRAP_ADMIN_USERNAME:
        raise HTTPException(status_code=400, detail=f"Cannot disable the bootstrap administrator account '{BOOTSTRAP_ADMIN_USERNAME}'.")
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
    return _public(user)


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
    if user.username == BOOTSTRAP_ADMIN_USERNAME:
        raise HTTPException(status_code=400, detail=f"Bootstrap administrator account '{BOOTSTRAP_ADMIN_USERNAME}' cannot be deleted.")
    if user.is_active and normalize_role(user.role) in ADMIN_ROLES and _active_admin_count(db, excluding_user_id=user.user_id) == 0:
        raise HTTPException(status_code=400, detail="Cannot delete the last active administrator.")

    username = user.username
    db.delete(user)
    db.commit()

    record_log(db, "RBAC", "ACTION", f"Admin '{admin.username}' deleted account '{username}'.",
               target=username, details={"by": admin.username})

    return {
        "status": "Success",
        "message": f"Operator account '{username}' has been removed from the platform."
    }
