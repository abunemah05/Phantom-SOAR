"""Encryption at rest for secrets stored in the database (integration credentials, TOTP seeds).

Values are Fernet tokens (AES-128-CBC + HMAC-SHA256, https://cryptography.io/en/latest/fernet/)
stored as ``enc:v1:<token>``. Anything without that prefix is treated as legacy plaintext and passed
through unchanged by ``decrypt_value`` so rows written before encryption keep working until
``encrypt_existing_secrets`` migrates them.

Keys
  PHANTOM_ENCRYPTION_KEY   one Fernet key (urlsafe base64, 32 bytes)  -- required in production
  PHANTOM_ENCRYPTION_KEYS  comma separated list for rotation: the FIRST key encrypts, every key
                           decrypts (cryptography.fernet.MultiFernet). Re-run encrypt_existing_secrets
                           after rotating to re-encrypt rows under the new primary key.
Outside production a stable fallback key is derived from PHANTOM_JWT_SECRET (with a warning); if that
is unset too, a random key is generated once and kept in a 0600 file so data survives restarts.
"""
import base64
import hashlib
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger(__name__)

PREFIX = "enc:v1:"

_lock = threading.Lock()
_cached: Optional[List[Fernet]] = None
_warned_fallback = False


class CryptoConfigError(RuntimeError):
    """The encryption key configuration is missing or invalid."""


class DecryptionError(ValueError):
    """An encrypted value could not be decrypted with any configured key."""


def is_production() -> bool:
    return os.getenv("PHANTOM_ENV", "").strip().lower() in ("production", "prod")


def _fallback_key() -> bytes:
    global _warned_fallback
    jwt_secret = os.getenv("PHANTOM_JWT_SECRET", "").strip()
    if not _warned_fallback:
        logger.warning(
            "PHANTOM_ENCRYPTION_KEY is not set: deriving the encryption key from a fallback. "
            "This is acceptable for development only; set PHANTOM_ENCRYPTION_KEY in production."
        )
        _warned_fallback = True
    if jwt_secret:
        digest = hashlib.pbkdf2_hmac("sha256", jwt_secret.encode("utf-8"), b"phantom-soar-encryption-v1", 200_000)
        return base64.urlsafe_b64encode(digest)
    path = Path(os.getenv("PHANTOM_DEV_KEY_FILE", "") or (Path(__file__).resolve().parent.parent / ".phantom_dev_key"))
    if path.exists():
        return path.read_text().strip().encode("ascii")
    key = Fernet.generate_key()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


def _load() -> List[Fernet]:
    raw_list = os.getenv("PHANTOM_ENCRYPTION_KEYS", "").strip()
    single = os.getenv("PHANTOM_ENCRYPTION_KEY", "").strip()
    raw_keys = [k.strip() for k in raw_list.split(",") if k.strip()] or ([single] if single else [])
    if not raw_keys:
        if is_production():
            raise CryptoConfigError("PHANTOM_ENCRYPTION_KEY is required when PHANTOM_ENV=production.")
        raw_keys = [_fallback_key().decode("ascii")]
    try:
        return [Fernet(k.encode("ascii")) for k in raw_keys]
    except (ValueError, TypeError) as exc:
        raise CryptoConfigError(
            "Invalid encryption key: generate one with "
            "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"`."
        ) from exc


def _fernets() -> List[Fernet]:
    global _cached
    if _cached is None:
        with _lock:
            if _cached is None:
                _cached = _load()
    return _cached


def reset_cache() -> None:
    """Forget loaded keys (tests, or after the environment changed)."""
    global _cached
    with _lock:
        _cached = None


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")


def is_encrypted(value: Optional[str]) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_value(value: str) -> str:
    """Encrypt under the primary key. Already-encrypted values are returned unchanged."""
    if value is None or value == "":
        return value
    if is_encrypted(value):
        return value
    token = _fernets()[0].encrypt(value.encode("utf-8")).decode("ascii")
    return PREFIX + token


def decrypt_value(value: Optional[str]) -> Optional[str]:
    """Plaintext passes through; ``enc:v1:`` values are decrypted with any configured key."""
    if not is_encrypted(value):
        return value
    token = value[len(PREFIX):].encode("ascii", errors="ignore")
    try:
        return MultiFernet(_fernets()).decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise DecryptionError("Stored secret cannot be decrypted with the configured encryption key(s).") from exc


def needs_rotation(value: Optional[str]) -> bool:
    """True for an encrypted value that the primary key cannot decrypt (it was sealed with an older key)."""
    if not is_encrypted(value):
        return False
    try:
        _fernets()[0].decrypt(value[len(PREFIX):].encode("ascii", errors="ignore"))
        return False
    except InvalidToken:
        return True


def rotate_value(value: str) -> str:
    """Re-encrypt under the primary key."""
    return encrypt_value(decrypt_value(value) or "")


def seal_secret(value: Optional[str], is_secret: bool) -> Optional[str]:
    """Value to store: encrypted when it is a non-empty secret."""
    if value and is_secret:
        return encrypt_value(value)
    return value


def encrypt_existing_secrets(db) -> dict:
    """Idempotently encrypt legacy plaintext secrets and re-seal rows under the primary key.

    Covers SystemConfig rows with is_secret and users.mfa_secret. Call once at startup.
    """
    from backend.models import SystemConfig, User  # local import: models import database

    counts = {"config": 0, "mfa": 0, "rotated": 0, "undecryptable": 0}
    for row in db.query(SystemConfig).filter(SystemConfig.is_secret.is_(True)).all():
        value = row.key_value or ""
        if not value:
            continue
        try:
            if not is_encrypted(value):
                row.key_value = encrypt_value(value)
                counts["config"] += 1
            elif needs_rotation(value):
                row.key_value = rotate_value(value)
                counts["rotated"] += 1
        except DecryptionError:
            counts["undecryptable"] += 1
            logger.error(f"Secret setting '{row.key_name}' cannot be decrypted with the configured key(s).")
    for user in db.query(User).filter(User.mfa_secret.isnot(None)).all():
        value = user.mfa_secret or ""
        if not value:
            continue
        try:
            if not is_encrypted(value):
                user.mfa_secret = encrypt_value(value)
                counts["mfa"] += 1
            elif needs_rotation(value):
                user.mfa_secret = rotate_value(value)
                counts["rotated"] += 1
        except DecryptionError:
            counts["undecryptable"] += 1
            logger.error(f"MFA secret of '{user.username}' cannot be decrypted with the configured key(s).")
    if any(counts[k] for k in ("config", "mfa", "rotated")):
        db.commit()
        logger.info(f"Encryption at rest: {counts}")
    return counts
