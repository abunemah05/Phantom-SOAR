import logging
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

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


def _make_engine(url: str):
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True)


DATABASE_URL = _normalize_url(settings.DATABASE_URL)
engine = _make_engine(DATABASE_URL)

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
        engine = _make_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
