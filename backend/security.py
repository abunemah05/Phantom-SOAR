import os
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

# --- Logout revocation (in-process denylist of token ids until they expire) ---
_revoked_jtis: Dict[str, float] = {}
_revoked_lock = threading.Lock()

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

def is_token_revoked(payload: Dict[str, Any]) -> bool:
    jti = payload.get("jti")
    if not jti:
        return False
    with _revoked_lock:
        return jti in _revoked_jtis
