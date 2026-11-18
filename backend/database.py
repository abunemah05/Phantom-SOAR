import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.types import TypeDecorator

from backend.config import settings

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
SQLITE_FALLBACK_URL = f"sqlite:///{REPO_ROOT / 'phantom_soar.db'}"

_TRUE = {"1", "true", "yes", "on"}


def _normalize_url(url: str) -> str:
    # Accept the Heroku-style "postgres://" scheme and pin the installed driver:
    # SQLAlchemy 2.1 maps a bare "postgresql://" to psycopg 3, which is not a dependency.
    for scheme in ("postgres://", "postgresql://"):
        if url.startswith(scheme):
            return "postgresql+psycopg2://" + url[len(scheme):]
    return url


def _redact(url: str) -> str:
    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "<unparseable DATABASE_URL>"


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        logger.warning(f"Ignoring non-numeric {name}; using {default}.")
        return default


def make_engine(url: str, *, enforce_foreign_keys: bool = True):
    """Create an engine with settings suited to the backend.

    SQLite: cross-thread use, a busy timeout, and PRAGMA foreign_keys=ON on every connection
    (SQLite ignores foreign keys, including ON DELETE CASCADE, unless asked per connection;
    https://www.sqlite.org/foreignkeys.html#fk_enable). Migrations pass enforce_foreign_keys=False
    because Alembic's batch mode recreates tables
    (https://alembic.sqlalchemy.org/en/latest/batch.html#dealing-with-referencing-foreign-keys).

    Everything else (Postgres): a bounded, recycled, pre-pinged pool. Sizes can be tuned with
    PHANTOM_DB_POOL_SIZE, PHANTOM_DB_MAX_OVERFLOW, PHANTOM_DB_POOL_RECYCLE and PHANTOM_DB_POOL_TIMEOUT.
    """
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})
        if enforce_foreign_keys:
            @event.listens_for(engine, "connect")
            def _sqlite_foreign_keys_on(dbapi_connection, _record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        return engine
    return create_engine(
        url,
        pool_size=_int_env("PHANTOM_DB_POOL_SIZE", 10),
        max_overflow=_int_env("PHANTOM_DB_MAX_OVERFLOW", 20),
        pool_recycle=_int_env("PHANTOM_DB_POOL_RECYCLE", 1800),
        pool_timeout=_int_env("PHANTOM_DB_POOL_TIMEOUT", 30),
        pool_pre_ping=True,
    )


_make_engine = make_engine  # backwards-compatible alias


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetime for SQLite and Postgres.

    Postgres stores TIMESTAMP WITH TIME ZONE; SQLite has no time zone type, so the value is stored
    as a UTC wall-clock string. Values read back are always aware UTC datetimes. A naive datetime
    handed to the database is taken to be UTC (the old naive columns held UTC), an aware one is
    converted to UTC.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise TypeError(f"UTCDateTime expects a datetime, got {type(value).__name__}")
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


DATABASE_URL = _normalize_url(settings.DATABASE_URL)
engine = make_engine(DATABASE_URL)

if not DATABASE_URL.startswith("sqlite"):
    try:
        with engine.connect():
            pass
    except Exception as e:
        allow_fallback = os.getenv("PHANTOM_ALLOW_SQLITE_FALLBACK", "").strip().lower() in _TRUE
        if not allow_fallback:
            raise RuntimeError(
                f"Cannot connect to the database at {_redact(DATABASE_URL)}: {e}. "
                "Fix DATABASE_URL (or unset it to use the local SQLite database), or set "
                "PHANTOM_ALLOW_SQLITE_FALLBACK=true to fall back to SQLite explicitly."
            ) from e
        logger.warning(
            f"Cannot connect to {_redact(DATABASE_URL)} ({e}); PHANTOM_ALLOW_SQLITE_FALLBACK is set, "
            f"falling back to {SQLITE_FALLBACK_URL}."
        )
        engine.dispose()
        DATABASE_URL = SQLITE_FALLBACK_URL
        engine = make_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope():
    """Transactional scope for code outside request handlers: commit on success, roll back on error."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
