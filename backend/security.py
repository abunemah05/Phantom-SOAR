import os
import re
import hmac
import hashlib
import logging
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import pyotp
import jwt
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

logger = logging.getLogger(__name__)

# --- Argon2 Hasher Configuration (NIST SP 800-63B Recommendation) ---
# Parameters: Memory = 64MB (65536 KB), Time iterations = 2, Parallelism = 2
argon2_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)


def _load_jwt_secret() -> str:
    secret = os.getenv("PHANTOM_JWT_SECRET", "").strip()
    if secret:
        return secret
    if os.getenv("PHANTOM_ENV", "").strip().lower() != "test":
        logger.warning(
            "PHANTOM_JWT_SECRET is not set: using a random per-process signing key. "
            "Sessions will not survive a restart and will not be shared between workers."
        )
    return secrets.token_urlsafe(64)


def _load_expiry_minutes() -> int:
    raw = os.getenv("PHANTOM_JWT_EXPIRE_MINUTES", "").strip()
    try:
        minutes = int(raw) if raw else 720
    except ValueError:
        logger.warning(f"Invalid PHANTOM_JWT_EXPIRE_MINUTES={raw!r}; using 720.")
        minutes = 720
    return max(1, minutes)


JWT_SECRET_KEY = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = _load_expiry_minutes()

# Claim set on tokens issued to users who must change their password first.
PASSWORD_CHANGE_CLAIM = "pwd_change_required"

# Legacy salt, only used to verify (and then upgrade) pre-Argon2 hashes.
LEGACY_SALT = "phantom_soar_salt_2026"

# Verified against when a username does not exist, so response time does not reveal valid usernames.
_DUMMY_HASH = argon2_hasher.hash(secrets.token_urlsafe(16))

# --- NIST SP 800-63B Compromised Credential Blocklist ---
# Common dictionary words, known breached passwords, and trivial keyboard patterns
COMPROMISED_PASSWORD_BLOCKLIST = {
    "password", "password123", "password1234", "12345678", "123456789", "1234567890",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "administrator", "admin123", "admin1234",
    "welcome123", "welcome2026", "phantomsoar", "phantomsoar1", "phantomsoar123",
    "phantomsoar1@", "admin1", "iloveyou123", "sunshine1", "princess1", "football1",
    "monkey123", "shadow123", "master123", "dragon123", "trustno1", "letmein123",
    "changeme123", "default123", "soc_analyst", "analyst123", "phantom123",
    "cybersecurity", "infosec123"
}

def hash_password(password: str) -> str:
    """Hash password using Argon2id (NIST SP 800-63B compliant)."""
    return argon2_hasher.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password against Argon2id hash.
    Falls back to the legacy salted SHA-256 format for credentials created before Argon2.
    """
    if not hashed_password or not plain_password:
        return False

    if hashed_password.startswith("$argon2"):
        try:
            return argon2_hasher.verify(hashed_password, plain_password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    legacy_hash = hashlib.sha256(f"{LEGACY_SALT}{plain_password}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_hash, hashed_password)

def password_needs_rehash(hashed_password: str) -> bool:
    """True for legacy SHA-256 hashes or Argon2 hashes with outdated parameters."""
    if not hashed_password or not hashed_password.startswith("$argon2"):
        return True
    try:
        return argon2_hasher.check_needs_rehash(hashed_password)
    except InvalidHashError:
        return True

def burn_password_check(plain_password: str) -> None:
    """Spend the same work as a real verification (used for unknown usernames)."""
    verify_password(plain_password or "x", _DUMMY_HASH)

def generate_temporary_password() -> str:
    """Random one-time password for new or reset accounts (must be changed at first sign-in)."""
    return secrets.token_urlsafe(15)

def is_compromised_password(password: str) -> bool:
    """
    Check if prospective password is in the known compromised blocklist
    or exhibits repetitive/sequential character sequences (NIST SP 800-63B 5.1.1.2).
    """
    normalized = password.strip().lower()
    if normalized in COMPROMISED_PASSWORD_BLOCKLIST:
        return True

    # Check for trivial dictionary prefixes common in breaches (e.g., password1234, admin2026)
    common_roots = [
        "password", "qwerty", "admin", "welcome", "letmein", "default",
        "phantomsoar", "changeme", "iloveyou", "dragon", "master"
    ]
    for root in common_roots:
        if normalized.startswith(root) and len(normalized) <= len(root) + 8:
            # Check if trailing characters are just digits, sequential or simple suffixes
            trailing = normalized[len(root):]
            if not trailing or trailing.isdigit() or trailing in "1234567890!@#$%":
                return True

    # Check for simple repetition (e.g., 'aaaaaaaa', '11111111')
    if len(set(normalized)) <= 2 and len(normalized) >= 8:
        return True

    # Check for simple 8+ char ascending sequences ('12345678', 'abcdefgh')
    seq1 = "01234567890123456789"
    seq2 = "abcdefghijklmnopqrstuvwxyz"
    if len(normalized) >= 8 and (normalized in seq1 or normalized in seq2):
        return True

    return False

def check_nist_password_policy(
    password: str,
    mfa_enabled: bool = False,
    username: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Strict NIST SP 800-63B Password Policy:
    1. Length over complexity:
       - Minimum 8 characters if MFA-enabled.
       - Minimum 15 characters for single-factor accounts.
       - Support up to 64+ characters (we allow up to 128).
    2. No arbitrary symbol/number composition rules enforced.
    3. Reject passwords found on compromised credential blocklists.
    4. Reject passwords containing the username.
    """
    length = len(password)
    min_length = 8 if mfa_enabled else 15

    if length < min_length:
        if mfa_enabled:
            return False, f"NIST policy requires at least 8 characters for MFA-enabled accounts (provided: {length})."
        else:
            return False, f"NIST policy requires at least 15 characters for single-factor accounts (provided: {length}). Enable MFA to use an 8-character password."

    if length > 128:
        return False, "Password exceeds maximum allowable length of 128 characters."

    if username and username.lower() in password.lower() and len(username) >= 4:
        return False, "Password cannot contain your username."

    if is_compromised_password(password):
        return False, "This password is known to be compromised or trivially predictable. Please choose a different passphrase."

    return True, "Password meets NIST SP 800-63B standards."

# --- MFA / TOTP Utilities (RFC 6238) ---
def generate_totp_secret() -> str:
    """Generate RFC 6238 compatible Base32 secret for TOTP."""
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str) -> str:
    """Generate TOTP URI for authenticator apps (Google Authenticator, Microsoft Authenticator, 1Password)."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="Phantom SOAR"
    )

def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP token with a 30-second drift tolerance window."""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(code.strip(), valid_window=1))

# --- JWT Session Tokens ---
def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT. Every token gets a unique jti so it can be revoked at logout."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta else timedelta(minutes=JWT_EXPIRATION_MINUTES))
    to_encode.update({"iat": now, "exp": expire})
    to_encode.setdefault("jti", secrets.token_urlsafe(16))
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a signed JWT (signature, expiry, required claims). None when invalid."""
    try:
        return jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError:
        return None

# --- Service-account API keys ---
# Format: phk_<8 hex lookup id>_<43 url-safe chars>. Only the lookup id and a SHA-256 digest are
# stored; the keys carry 256 bits of entropy, so a fast digest is appropriate (no password stretching).
API_KEY_PREFIX = "phk_"


def generate_api_key() -> Tuple[str, str, str]:
    """Returns (plaintext key shown once, lookup prefix to store, digest to store)."""
    lookup = f"{API_KEY_PREFIX}{secrets.token_hex(4)}"
    key = f"{lookup}_{secrets.token_urlsafe(32)}"
    return key, lookup, hash_api_key(key)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def api_key_lookup_prefix(key: str) -> Optional[str]:
    """The stored lookup prefix of a well-formed key, else None."""
    if not key or not key.startswith(API_KEY_PREFIX):
        return None
    lookup, sep, secret = key.partition("_")[2].partition("_")
    if not sep or len(lookup) != 8 or not secret:
        return None
    return f"{API_KEY_PREFIX}{lookup}"


def verify_api_key(key: str, stored_hash: Optional[str]) -> bool:
    if not key or not stored_hash:
        return False
    return hmac.compare_digest(hash_api_key(key), stored_hash)


# --- Ingest tokens (per-sender webhook credentials) -----------------------------------------------------
# Format: phi_<8 hex lookup id>_<43 url-safe chars>; only the lookup id and a SHA-256 digest are stored.
INGEST_TOKEN_PREFIX = "phi_"
MIN_LEGACY_INGEST_TOKEN_LENGTH = 32


def generate_ingest_token() -> Tuple[str, str, str]:
    """Returns (plaintext shown once, lookup prefix, digest)."""
    lookup = f"{INGEST_TOKEN_PREFIX}{secrets.token_hex(4)}"
    token = f"{lookup}_{secrets.token_urlsafe(32)}"
    return token, lookup, hashlib.sha256(token.encode("utf-8")).hexdigest()


def ingest_token_lookup_prefix(token: str) -> Optional[str]:
    if not token or not token.startswith(INGEST_TOKEN_PREFIX):
        return None
    lookup, sep, secret = token[len(INGEST_TOKEN_PREFIX):].partition("_")
    if not sep or len(lookup) != 8 or not secret:
        return None
    return f"{INGEST_TOKEN_PREFIX}{lookup}"


def hash_ingest_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- Production configuration check ---------------------------------------------------------
class SecurityConfigError(RuntimeError):
    """Raised at startup when the environment is unsafe to run in production."""


def is_production() -> bool:
    return os.getenv("PHANTOM_ENV", "").strip().lower() in ("production", "prod")


def validate_security_config() -> None:
    """Refuse to start in production without a strong JWT secret and an encryption key.

    Called by the application at startup. Outside production it only logs warnings.
    """
    problems = []
    jwt_secret = os.getenv("PHANTOM_JWT_SECRET", "").strip()
    if len(jwt_secret) < 32:
        problems.append("PHANTOM_JWT_SECRET must be set to a random value of at least 32 characters")
    has_key = bool(os.getenv("PHANTOM_ENCRYPTION_KEY", "").strip() or os.getenv("PHANTOM_ENCRYPTION_KEYS", "").strip())
    if not has_key:
        problems.append("PHANTOM_ENCRYPTION_KEY must be set (Fernet key for secrets at rest)")
    else:
        try:
            from backend import crypto
            crypto.reset_cache()
            crypto._fernets()
        except Exception as exc:
            problems.append(f"encryption key is invalid: {exc}")
    legacy = os.getenv("PHANTOM_INGEST_TOKEN", "").strip()
    if legacy and len(legacy) < 32:
        logger.warning("PHANTOM_INGEST_TOKEN is shorter than 32 characters and is ignored; create per-sender "
                       "ingest tokens with POST /api/ingest-tokens instead.")
    if problems:
        message = "Insecure configuration: " + "; ".join(problems) + "."
        if is_production():
            raise SecurityConfigError(message)
        logger.warning(message + " (tolerated outside production)")


def mfa_required_for_admin() -> bool:
    """Optional policy: administrators must have MFA enabled (setting require_mfa_for_admin)."""
    from backend.integration_config import get_setting
    raw = get_setting("require_mfa_for_admin") or os.getenv("PHANTOM_REQUIRE_MFA_FOR_ADMIN", "")
    return raw.strip().lower() in ("1", "true", "yes", "on")


# --- DB helpers shared by revocation and TOTP replay ---------------------------------------------
def _naive_utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def _with_security_db(fn):
    """Run fn(session) on a short-lived session, creating the security tables once if they are missing."""
    from backend import security_models
    from backend.database import SessionLocal

    for attempt in (1, 2):
        db = SessionLocal()
        try:
            return fn(db)
        except (OperationalError, ProgrammingError) as exc:
            db.rollback()
            if attempt == 2 or is_production():
                raise
            logger.warning(f"Security tables missing ({exc.__class__.__name__}); creating them.")
            security_models.ensure_tables()
        finally:
            db.close()


# --- TOTP replay protection (RFC 6238 section 5.2: a code is accepted once) --------------------------
_used_totp_fallback: Dict[Tuple[str, int], float] = {}


def consume_totp_code(db, subject: str, secret: str, code: str) -> bool:
    """Verify a TOTP code and mark its time step as used for `subject`. A replayed code is rejected."""
    if not secret or not code:
        return False
    code = code.strip()
    totp = pyotp.TOTP(secret)
    step_now = int(time.time() // 30)
    matched = None
    for step in (step_now, step_now - 1, step_now + 1):
        if hmac.compare_digest(totp.at(step * 30), code):
            matched = step
            break
    if matched is None:
        return False

    from backend.security_models import UsedTotpCode

    def _record(session) -> bool:
        session.query(UsedTotpCode).filter(UsedTotpCode.time_step < step_now - 20).delete(synchronize_session=False)
        session.add(UsedTotpCode(subject=subject, time_step=matched))
        try:
            session.commit()
            return True
        except IntegrityError:
            session.rollback()
            return False

    try:
        return _with_security_db(_record)
    except Exception as exc:  # DB unavailable: still stop replays inside this process
        logger.error(f"TOTP replay store unavailable ({exc.__class__.__name__}); using process memory.")
        key = (subject, matched)
        if key in _used_totp_fallback:
            return False
        _used_totp_fallback[key] = time.time()
        return True


# --- Session revocation (persisted, with an in-memory cache) -------------------------------------------
_revoked_jtis: Dict[str, float] = {}
_revoked_lock = threading.Lock()


def _insert_revoked(jti: str, exp: float) -> bool:
    """Persist a revoked id. False when it was already present."""
    from backend.security_models import RevokedToken

    def _insert(db) -> bool:
        db.query(RevokedToken).filter(RevokedToken.expires_at < _naive_utc(time.time())).delete(synchronize_session=False)
        db.add(RevokedToken(jti=jti, expires_at=_naive_utc(exp)))
        try:
            db.commit()
            return True
        except IntegrityError:
            db.rollback()
            return False

    try:
        return _with_security_db(_insert)
    except Exception as exc:
        logger.error(f"Could not persist token revocation ({exc.__class__.__name__}); kept in process memory only.")
        return True


def revoke_token(payload: Dict[str, Any]) -> None:
    jti = payload.get("jti")
    if not jti:
        return
    exp = float(payload.get("exp") or (time.time() + JWT_EXPIRATION_MINUTES * 60))
    with _revoked_lock:
        now = time.time()
        for stale in [k for k, v in _revoked_jtis.items() if v < now]:
            _revoked_jtis.pop(stale, None)
        _revoked_jtis[jti] = exp
    _insert_revoked(jti, exp)


def is_token_revoked(payload: Dict[str, Any]) -> bool:
    jti = payload.get("jti")
    if not jti:
        return False
    with _revoked_lock:
        exp = _revoked_jtis.get(jti)
        if exp is not None and exp >= time.time():
            return True
    from backend.security_models import RevokedToken

    try:
        row_exp = _with_security_db(lambda db: db.query(RevokedToken.expires_at).filter(RevokedToken.jti == jti).first())
    except Exception as exc:
        logger.error(f"Revocation lookup failed ({exc.__class__.__name__}); relying on process memory.")
        return False
    if row_exp is None:
        return False
    with _revoked_lock:  # another worker revoked it: cache the positive answer
        _revoked_jtis[jti] = payload.get("exp") or (time.time() + 3600)
    return True


def purge_expired_revocations() -> int:
    """Delete revocation rows whose token has expired anyway. Returns the number removed."""
    from backend.security_models import RevokedToken

    def _purge(db) -> int:
        n = db.query(RevokedToken).filter(RevokedToken.expires_at < _naive_utc(time.time())).delete(synchronize_session=False)
        db.commit()
        return n

    return _with_security_db(_purge)


def forget_revocation_cache() -> None:
    """Drop the in-memory cache only (simulates a restart in tests)."""
    with _revoked_lock:
        _revoked_jtis.clear()


# --- Short-lived confirmation tokens for destructive actions ---------------------------------------
# Signed with a key derived from the JWT secret, so a confirmation token can never be used as a session
# token (and vice versa). One use only: the id is recorded in the revocation table.
def _confirmation_key() -> str:
    return hmac.new(JWT_SECRET_KEY.encode("utf-8"), b"phantom-confirmation-token-v1", hashlib.sha256).hexdigest()


def issue_confirmation_token(purpose: str, subject: str, session_id: str, ttl_seconds: int = 120) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "purpose": purpose, "sub": subject, "sid": session_id or "",
        "iat": now, "exp": now + timedelta(seconds=ttl_seconds), "jti": "c:" + secrets.token_urlsafe(16),
    }
    return jwt.encode(claims, _confirmation_key(), algorithm="HS256")


def consume_confirmation_token(token: str, purpose: str, subject: str, session_id: str) -> bool:
    try:
        claims = jwt.decode(token or "", _confirmation_key(), algorithms=["HS256"],
                            options={"require": ["exp", "iat", "sub", "jti"]})
    except jwt.PyJWTError:
        return False
    if claims.get("purpose") != purpose or claims.get("sub") != subject or claims.get("sid") != (session_id or ""):
        return False
    return _insert_revoked(claims["jti"], float(claims["exp"]))


# --- Masking for read-only audiences --------------------------------------------------------------------
_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|authorization|credential|cookie|session[_-]?id|private[_-]?key|ssn)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_CRED_ASSIGNMENT = re.compile(
    r"(?i)\b(pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|token|auth(?:orization)?)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT_LIKE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_AWS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL)
REDACTED = "[REDACTED]"


def mask_text(value: str) -> str:
    value = _PRIVATE_KEY.sub(REDACTED, value)
    value = _JWT_LIKE.sub(REDACTED, value)
    value = _AWS_KEY.sub(REDACTED, value)
    value = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", value)
    value = _CRED_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", value)
    return _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", value)


def mask_sensitive(obj: Any) -> Any:
    """Copy of a JSON-like structure with secrets, credential patterns and e-mail local parts masked."""
    if isinstance(obj, dict):
        out = {}
        for key, val in obj.items():
            if isinstance(key, str) and _SENSITIVE_KEY.search(key) and not isinstance(val, (dict, list)):
                out[key] = REDACTED if val not in (None, "") else val
            else:
                out[key] = mask_sensitive(val)
        return out
    if isinstance(obj, list):
        return [mask_sensitive(v) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj)
    return obj
