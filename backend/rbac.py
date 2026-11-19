"""Account-management policy: who may change whom.

One place, pure functions, no database and no FastAPI. `backend/routers/users.py` loads the accounts,
calls `decide()` and enforces the answer; the console shows the same answer (the `account_actions`
field of GET /api/users), so the rules cannot drift between screen and server. The reasoning behind
each rule, with sources, is in docs/ACCESS_CONTROL.md.

Rules enforced here (the numbers match docs/ACCESS_CONTROL.md):

  R1  An administrator cannot change their own role, disable or delete themselves, reset their own password
      through the admin API (use change-password, which proves the old password) or flag themselves.
  R2  The bootstrap (break-glass) administrator is always an active administrator: not demoted, disabled or deleted.
  R3  The last active administrator can never be demoted, disabled or deleted. (Races are closed in users.py.)
  R4  Service / AI-agent accounts cannot be given a human role, cannot become humans, cannot be administrators,
      have no password to reset, and never pass an admin check (dependencies.py refuses them before this module runs).
  R5  A sensitive change to ANOTHER administrator (role, enable/disable, password reset, compromised flag, delete),
      or a grant of the administrator role to anyone (promotion or creating an Admin account), needs a step-up: the acting admin re-enters their own password
      (and a fresh TOTP code when they have MFA). Rejected attempts and accepted changes are audit-logged.
  R6  Only named roles can be assigned; role names cannot be invented, and the AI-agent role is never assignable
      to a human account.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Optional

from backend.dependencies import (
    CANONICAL_ROLES,
    ROLE_ADMIN,
    SERVICE_ROLES,
    is_known_role,
    normalize_role,
    role_level,
)

# --- Step-up policy for the two grants outside PUT /users/{id} -----------------------------------------------------
# Creating an account with the Admin role and deleting another administrator are as sensitive as changing an
# administrator's role, so both need the acting admin's step-up confirmation (R5). The constants are the single place
# that says so; they are not configuration and must stay True.
STEP_UP_ON_ADMIN_CREATE = True
STEP_UP_ON_ADMIN_DELETE = True


class Action(str, Enum):
    CREATE_USER = "create_user"
    CREATE_SERVICE_ACCOUNT = "create_service_account"
    CHANGE_ROLE = "change_role"
    SET_ACTIVE = "set_active"
    SET_COMPROMISED = "set_compromised"  # also POST /flag-compromised (value True)
    RESET_PASSWORD = "reset_password"
    UNLOCK = "unlock"
    DELETE = "delete"
    ROTATE_KEY = "rotate_key"
    SERVICE_POLICY = "service_policy"


# Fields PUT /api/users/{id} accepts. Anything else is refused (mass-assignment protection, OWASP).
UPDATABLE_FIELDS = frozenset({"role", "is_active", "compromised_reset_required", "confirmation"})
CREATABLE_FIELDS = frozenset({"username", "role", "mfa_enabled", "confirmation"})  # mfa_enabled is accepted but ignored
SERVICE_CREATABLE_FIELDS = frozenset({"username", "expires_in_days", "ip_allowlist"})


class PolicyViolation(Exception):
    """A request the policy refuses. `code` is machine-readable and stable; `message` is for people."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Subject:
    """What the policy needs to know about an account."""
    user_id: int
    username: str
    role: str
    is_active: bool = True
    is_service_account: bool = False
    is_bootstrap: bool = False

    @property
    def level(self) -> str:
        return "service" if self.is_service_account else role_level(self.role)

    @property
    def is_admin(self) -> bool:
        return self.level == "admin"

    @property
    def is_active_admin(self) -> bool:
        return self.is_admin and self.is_active


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str = "ok"
    message: str = ""
    step_up: bool = False  # the acting admin must re-confirm their own credentials
    reason: str = ""  # why a step-up is required (shown in the console and written to the audit log)

    def as_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "code": self.code, "reason": self.message or self.reason or None,
                "step_up": self.step_up}


def _deny(code: str, message: str) -> Decision:
    return Decision(False, code, message)


def _allow(step_up: bool = False, reason: str = "") -> Decision:
    return Decision(True, "ok", "", step_up, reason if step_up else "")


# --- Roles (R6) ---------------------------------------------------------------------------------------------------
def assignable_roles() -> tuple:
    """Roles an administrator may assign to a human account: the canonical roles, nothing else is advertised."""
    return CANONICAL_ROLES


def role_unchanged(current: Optional[str], requested: Optional[str]) -> bool:
    """True when `requested` is absent or is the account's stored role (whitespace-collapsed, exact spelling).

    Checked BEFORE assignability, so a form that resends the current role is a harmless no-op even when that role is a
    legacy name ("Sys Admin") that could not be assigned today."""
    return requested is None or " ".join(requested.split()) == " ".join((current or "").split())


def validate_assignable_role(role: Optional[str]) -> str:
    """The role string to store for a human account, or PolicyViolation.

    Canonical roles are matched case-insensitively and stored with their canonical spelling. Legacy aliases of
    NON-administrator roles that older databases and UI builds use are still accepted; legacy administrator aliases
    ("Sys Admin", "SOC Lead / Admin", ...) are not, so the only string that grants administration is "Admin".
    The AI-agent role and anything unknown are refused.
    """
    collapsed = " ".join((role or "").split())
    if not collapsed:
        raise PolicyViolation("role_required", "Role cannot be empty.")
    normalized = normalize_role(collapsed)
    allowed = ", ".join(CANONICAL_ROLES)
    if normalized in SERVICE_ROLES:
        raise PolicyViolation(
            "service_role_not_assignable",
            f"The '{collapsed}' role belongs to service accounts and cannot be given to a person. Assign one of: {allowed}.")
    if not is_known_role(collapsed):
        raise PolicyViolation("unknown_role", f"Unknown role '{collapsed[:60]}'. Assign one of: {allowed}.")
    for canonical in CANONICAL_ROLES:
        if normalize_role(canonical) == normalized:
            return canonical
    if role_level(collapsed) == "admin":
        raise PolicyViolation(
            "legacy_admin_alias", f"'{collapsed}' is a legacy administrator name. Assign '{ROLE_ADMIN}' instead.")
    return collapsed


def unknown_fields(extra: Optional[Dict[str, Any]], allowed: Iterable[str] = UPDATABLE_FIELDS) -> list:
    """Names in `extra` that are not whitelisted (mass assignment: is_service_account, username, api_key_hash, ...)."""
    allowed_set = set(allowed)
    return sorted(str(k)[:40] for k in (extra or {}) if k not in allowed_set)


# --- The decision (R1-R5) -----------------------------------------------------------------------------------------
def actor_denial(actor: Subject) -> Optional[Decision]:
    """None when `actor` may manage accounts at all: an active, human administrator. Service accounts never are (R4)."""
    if actor.is_service_account:
        return _deny("service_account_cannot_manage",
                     "Service accounts cannot manage accounts, roles or permissions.")
    if not actor.is_active or not actor.is_admin:
        return _deny("actor_not_admin", "Only active administrators can manage accounts.")
    return None


def decide(
    action: Action,
    actor: Subject,
    target: Optional[Subject] = None,
    *,
    new_role: Optional[str] = None,
    new_is_active: Optional[bool] = None,
    new_compromised: Optional[bool] = None,
    other_active_admins: int = 1,
) -> Decision:
    """May `actor` perform `action` on `target`?

    `other_active_admins` is the number of active, human administrators other than `target`
    (the acting administrator counts). New values are only needed by the action that uses them.
    """
    refused = actor_denial(actor)
    if refused is not None:
        return refused

    if action is Action.CREATE_SERVICE_ACCOUNT:
        return _allow()

    if action is Action.CREATE_USER:
        level = role_level(new_role)
        if level == "admin":
            return _allow(STEP_UP_ON_ADMIN_CREATE, "Granting the administrator role.")
        return _allow()

    if target is None:
        return _deny("target_required", "This action needs an account.")

    is_self = actor.user_id == target.user_id

    # Service accounts (R4): fixed role, no password, only key / status / policy management.
    if target.is_service_account:
        if action is Action.CHANGE_ROLE:
            return _deny("service_account_role_fixed",
                         "A service account's role is fixed. It cannot be changed or made an administrator; create a separate account instead.")
        if action in (Action.RESET_PASSWORD, Action.UNLOCK, Action.SET_COMPROMISED):
            return _deny("service_account_no_password",
                         "Service accounts have no password: rotate their API key instead.")
        return _allow()  # SET_ACTIVE, DELETE, ROTATE_KEY, SERVICE_POLICY: no step-up, still audit-logged

    # From here on the target is a person.
    if action in (Action.ROTATE_KEY, Action.SERVICE_POLICY):
        return _deny("not_a_service_account", "Only service accounts have an API key.")

    removes_admin = target.is_active_admin
    last_admin = removes_admin and other_active_admins < 1

    if action is Action.CHANGE_ROLE:
        if role_unchanged(target.role, new_role):
            return _allow()  # nothing changes
        new_level = role_level(new_role)
        if normalize_role(new_role) in SERVICE_ROLES:
            return _deny("service_role_not_assignable", "The AI-agent role belongs to service accounts only.")
        if is_self:
            return _deny("self_role_change",
                         "You cannot change your own role. Ask another administrator.")
        if target.is_admin and new_level != "admin":
            if target.is_bootstrap:
                return _deny("bootstrap_protected",
                             f"'{target.username}' is the bootstrap administrator and must stay an administrator.")
            if last_admin:
                return _deny("last_admin", "This would leave the platform without an active administrator.")
        needs = target.is_admin or new_level == "admin"
        why = "Granting the administrator role." if new_level == "admin" and not target.is_admin else "Changing another administrator's role."
        return _allow(needs, why)

    if action is Action.SET_ACTIVE:
        if new_is_active is None or bool(new_is_active) == bool(target.is_active):
            return _allow()
        if new_is_active is False:
            if is_self:
                return _deny("self_disable", "You cannot disable your own account.")
            if target.is_bootstrap:
                return _deny("bootstrap_protected",
                             f"The bootstrap administrator account '{target.username}' cannot be disabled.")
            if last_admin:
                return _deny("last_admin", "This would leave the platform without an active administrator.")
        return _allow(target.is_admin, "Changing another administrator's active state.")

    if action is Action.DELETE:
        if is_self:
            return _deny("self_delete", "You cannot delete your own account.")
        if target.is_bootstrap:
            return _deny("bootstrap_protected",
                         f"Bootstrap administrator account '{target.username}' cannot be deleted.")
        if last_admin:
            return _deny("last_admin", "Cannot delete the last active administrator.")
        return _allow(target.is_admin and STEP_UP_ON_ADMIN_DELETE, "Deleting another administrator.")

    if action is Action.RESET_PASSWORD:
        if is_self:
            return _deny("self_password_reset",
                         "Use 'change password' for your own account: it proves your current password. "
                         "A reset through the admin API would bypass that proof.")
        return _allow(target.is_admin, "Resetting another administrator's password.")

    if action is Action.SET_COMPROMISED:
        if is_self:
            return _deny("self_compromised_flag",
                         "Change your own password instead of flagging or unflagging your own account.")
        return _allow(target.is_admin, "Flagging another administrator as compromised.")

    if action is Action.UNLOCK:
        return _allow()

    return _deny("unknown_action", "Unknown account action.")


def decide_update(
    actor: Subject,
    target: Subject,
    *,
    new_role: Optional[str] = None,
    new_is_active: Optional[bool] = None,
    new_compromised: Optional[bool] = None,
    other_active_admins: int = 1,
) -> Decision:
    """PUT /users/{id}: every requested field must be allowed; one refusal refuses the whole request.
    A step-up is needed when any single field needs one. `new_compromised` is passed only when it is a change."""
    refused = actor_denial(actor)
    if refused is not None:
        return refused
    checks = []
    if new_role is not None:
        checks.append(decide(Action.CHANGE_ROLE, actor, target, new_role=new_role, other_active_admins=other_active_admins))
    if new_is_active is not None:
        checks.append(decide(Action.SET_ACTIVE, actor, target, new_is_active=new_is_active, other_active_admins=other_active_admins))
    if new_compromised is not None:
        checks.append(decide(Action.SET_COMPROMISED, actor, target, new_compromised=new_compromised))
    for check in checks:
        if not check.allowed:
            return check
    needing = [c for c in checks if c.step_up]
    if needing:
        return Decision(True, "ok", "", True, needing[0].reason)
    return _allow()


def row_permissions(actor: Subject, target: Subject, other_active_admins: int) -> Dict[str, Dict[str, Any]]:
    """What the console may offer on this account's row: {action: {allowed, reason, step_up}}.

    Role change is probed with a non-administrator role (the console adds the rule that promoting to administrator
    always needs a step-up); status change is probed with the opposite of the current state."""
    def pick(action: Action, **kw) -> Dict[str, Any]:
        return decide(action, actor, target, other_active_admins=other_active_admins, **kw).as_dict()

    probe_role = "Security Engineer" if normalize_role(target.role) == normalize_role("SOC Analyst") else "SOC Analyst"
    return {
        Action.CHANGE_ROLE.value: pick(Action.CHANGE_ROLE, new_role=probe_role),
        Action.SET_ACTIVE.value: pick(Action.SET_ACTIVE, new_is_active=not target.is_active),
        Action.RESET_PASSWORD.value: pick(Action.RESET_PASSWORD),
        Action.SET_COMPROMISED.value: pick(Action.SET_COMPROMISED, new_compromised=True),
        Action.UNLOCK.value: pick(Action.UNLOCK),
        Action.DELETE.value: pick(Action.DELETE),
        Action.ROTATE_KEY.value: pick(Action.ROTATE_KEY),
        Action.SERVICE_POLICY.value: pick(Action.SERVICE_POLICY),
    }
