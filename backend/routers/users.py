import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.schemas import UserResponse, UserCreateRequest, UserUpdateRequest
from backend.security import hash_password
from backend.dependencies import require_admin
from backend.routers.auth import ensure_default_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["User Accounts & Access Management (Admin Only)"])

DEFAULT_NEW_USER_PASSWORD = "PhantomSOAR1@"

@router.get("", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] List all operator accounts with roles, security flags, and MFA status.
    Strictly restricted to SOC Administrators.
    """
    ensure_default_user(db)
    users = db.query(User).order_by(User.user_id.asc()).all()
    return [u.to_dict() for u in users]

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest, 
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Provision a new operator account with specified role (Admin or SOC Analyst).
    Initial password is set to 'PhantomSOAR1@' and flagged for mandatory change upon first login.
    """
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty.")

    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(
            status_code=400, 
            detail=f"Operator username '{username}' already exists in the system."
        )

    new_user = User(
        username=username,
        password_hash=hash_password(DEFAULT_NEW_USER_PASSWORD),
        role=payload.role.strip() or "SOC Analyst",
        must_change_password=True,
        is_active=True,
        mfa_enabled=payload.mfa_enabled,
        password_changed_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(f"Admin '{admin.username}' provisioned new account: '{username}' with role '{new_user.role}'.")

    return new_user.to_dict()

@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int, 
    payload: UserUpdateRequest, 
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Update role, activation status, or security flags for an operator.
    """
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    if payload.role is not None:
        user.role = payload.role.strip()

    if payload.is_active is not None:
        if user.username == "abunemah" and not payload.is_active:
            raise HTTPException(status_code=400, detail="Cannot disable root administrator account 'abunemah'.")
        user.is_active = payload.is_active

    if payload.compromised_reset_required is not None:
        user.compromised_reset_required = payload.compromised_reset_required
        if payload.compromised_reset_required:
            user.must_change_password = True

    db.commit()
    db.refresh(user)

    logger.info(f"Admin '{admin.username}' updated account #{user_id} ('{user.username}').")
    return user.to_dict()

@router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: int, 
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Reset an operator's password to 'PhantomSOAR1@' and flag for mandatory change.
    """
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    user.password_hash = hash_password(DEFAULT_NEW_USER_PASSWORD)
    user.must_change_password = True
    user.compromised_reset_required = False
    db.commit()

    logger.info(f"Admin '{admin.username}' reset password for operator '{user.username}'.")

    return {
        "status": "Success",
        "message": f"Password for operator '{user.username}' has been reset to '{DEFAULT_NEW_USER_PASSWORD}'. Operator must change password upon next login.",
        "default_password": DEFAULT_NEW_USER_PASSWORD
    }

@router.post("/{user_id}/flag-compromised")
def flag_account_compromised(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] NIST SP 800-63B Compliance:
    Flag account as suspected compromised. Requires immediate password reset on next authentication.
    """
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    user.compromised_reset_required = True
    user.must_change_password = True
    db.commit()

    logger.warning(f"Admin '{admin.username}' flagged operator '{user.username}' as suspected compromised.")

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
    """
    [Admin Only] Delete an operator account. Root admin 'abunemah' is permanently protected.
    """
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    if user.username == "abunemah":
        raise HTTPException(status_code=400, detail="Root administrator account 'abunemah' cannot be deleted.")

    username = user.username
    db.delete(user)
    db.commit()

    logger.info(f"Admin '{admin.username}' removed operator account '{username}'.")

    return {
        "status": "Success",
        "message": f"Operator account '{username}' has been removed from the platform."
    }
