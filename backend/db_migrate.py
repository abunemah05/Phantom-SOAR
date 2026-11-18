"""Database schema management: Alembic migrations plus a safe upgrade path for old databases.

Entry points
  prepare_database()      what the application runs at startup (migrations; fast create_all when PHANTOM_ENV=test)
  run_migrations()        bring a database to head under a cross-process lock
  python -m backend.db_migrate [upgrade|current|check]

Databases created before Alembic existed (create_all plus the old SQLite-only ALTER shim) have tables
but no alembic_version table. run_migrations() recognises them, adds the columns the shim used to add,
creates any table that is missing (revision 0001 only creates tables that do not exist yet), and then
upgrades to head, so existing data is kept.
"""
import contextlib
import importlib
import logging
import os
import sys
import time
from pathlib import Path
from typing import Iterator, Optional

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.operations import Operations
from sqlalchemy.engine import Connection, Engine

from backend import database as app_database
from backend.config import settings

logger = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).resolve().parent
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
SCRIPT_LOCATION = BACKEND_DIR / "alembic"

# LEAD: every module that defines ORM models must be listed here so create_all (test mode) and
# `alembic revision --autogenerate` (via alembic/env.py) see all tables.
MODEL_MODULES = (
    "backend.models",
)

# Arbitrary constant identifying "Phantom SOAR schema migration" for pg_advisory_lock.
POSTGRES_ADVISORY_LOCK_ID = 7_243_100_017
LOCK_TIMEOUT_SECONDS = 300


def import_models() -> None:
    for module in MODEL_MODULES:
        importlib.import_module(module)


def build_config() -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    cfg.attributes["configure_logger"] = False  # keep the application's logging configuration
    return cfg


def head_revision() -> str:
    return ScriptDirectory.from_config(build_config()).get_current_head()


# ----------------------------------------------------------------------------------------------
# Locking so several processes starting together do not race
# ----------------------------------------------------------------------------------------------

def _sqlite_lock_path(engine: Engine) -> Optional[Path]:
    database = engine.url.database
    if not database or database == ":memory:" or database.startswith("file::memory:"):
        return None
    return Path(str(database) + ".migrate.lock")


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float = LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    deadline = time.monotonic() + timeout
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"Timed out waiting for migration lock {path}")
                    time.sleep(0.2)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"Timed out waiting for migration lock {path}")
                    time.sleep(0.2)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


@contextlib.contextmanager
def migration_lock(engine: Engine) -> Iterator[None]:
    """Postgres: session-level advisory lock on a dedicated connection. SQLite: lock file next to the database."""
    if engine.dialect.name == "postgresql":
        # https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS
        with engine.connect() as lock_conn:
            lock_conn.execute(sa.text("SELECT pg_advisory_lock(:id)"), {"id": POSTGRES_ADVISORY_LOCK_ID})
            lock_conn.commit()
            try:
                yield
            finally:
                lock_conn.rollback()
                lock_conn.execute(sa.text("SELECT pg_advisory_unlock(:id)"), {"id": POSTGRES_ADVISORY_LOCK_ID})
                lock_conn.commit()
    elif engine.dialect.name == "sqlite":
        path = _sqlite_lock_path(engine)
        if path is None:
            yield
        else:
            with _file_lock(path):
                yield
    else:
        yield


# ----------------------------------------------------------------------------------------------
# Legacy (pre-Alembic) databases
# ----------------------------------------------------------------------------------------------

def _col(name, type_, **kw):
    return sa.Column(name, type_, **kw)


def _not_null(default):
    return {"nullable": False, "server_default": default}


# Exactly the columns the removed SQLite ALTER shim in main.py used to add, as (table, column).
# Columns with a default are added NOT NULL so they already match the models (SQLite allows
# ADD COLUMN NOT NULL when a constant default is given).
LEGACY_SHIM_COLUMNS = (
    ("alerts", lambda: _col("analyst_decision", sa.String(100), nullable=True)),
    ("alerts", lambda: _col("assigned_analyst", sa.String(50), nullable=True)),
    ("alerts", lambda: _col("resolved_by", sa.String(50), nullable=True)),
    ("alerts", lambda: _col("resolved_at", sa.DateTime(), nullable=True)),
    ("users", lambda: _col("must_change_password", sa.Boolean(), **_not_null(sa.false()))),
    ("users", lambda: _col("is_active", sa.Boolean(), **_not_null(sa.true()))),
    ("users", lambda: _col("mfa_enabled", sa.Boolean(), **_not_null(sa.false()))),
    ("users", lambda: _col("mfa_secret", sa.String(64), nullable=True)),
    ("users", lambda: _col("password_changed_at", sa.DateTime(), nullable=True)),  # back-filled below
    ("users", lambda: _col("compromised_reset_required", sa.Boolean(), **_not_null(sa.false()))),
    ("users", lambda: _col("failed_login_attempts", sa.Integer(), **_not_null(sa.text("0")))),
    ("users", lambda: _col("locked_until", sa.DateTime(), nullable=True)),
    ("users", lambda: _col("is_service_account", sa.Boolean(), **_not_null(sa.false()))),
    ("users", lambda: _col("api_key_hash", sa.String(255), nullable=True)),
    ("users", lambda: _col("api_key_prefix", sa.String(16), nullable=True)),
    ("ioc_artifacts", lambda: _col("verdict", sa.String(20), **_not_null(sa.text("'Unknown'")))),
    ("ioc_artifacts", lambda: _col("enrichment_status", sa.String(30), **_not_null(sa.text("'pending'")))),
    ("ioc_artifacts", lambda: _col("tip_results", sa.JSON(), nullable=True)),
    ("containment_actions", lambda: _col("executed_by", sa.String(50), **_not_null(sa.text("'System'")))),
    ("containment_actions", lambda: _col("target", sa.String(255), nullable=True)),
    ("containment_actions", lambda: _col("connector", sa.String(50), nullable=True)),
    ("containment_actions", lambda: _col("execution_mode", sa.String(20), nullable=True)),
    ("containment_actions", lambda: _col("details", sa.JSON(), nullable=True)),
)

# Indexes of the baseline that belong to shim-added columns.
LEGACY_SHIM_INDEXES = (
    ("ix_alerts_assigned_analyst", "alerts", "assigned_analyst"),
    ("ix_alerts_resolved_by", "alerts", "resolved_by"),
    ("ix_users_api_key_prefix", "users", "api_key_prefix"),
    ("ix_containment_actions_executed_by", "containment_actions", "executed_by"),
)


def is_legacy_database(conn: Connection) -> bool:
    """Tables exist but Alembic has never been applied."""
    names = set(sa.inspect(conn).get_table_names())
    return "alembic_version" not in names and bool(names & {"users", "alerts", "system_configs"})


def add_legacy_shim_columns(conn: Connection) -> list:
    """Add the columns the old SQLite ALTER shim added (works on SQLite and Postgres). Returns what was added."""
    inspector = sa.inspect(conn)
    tables = set(inspector.get_table_names())
    ops = Operations(MigrationContext.configure(conn))
    added = []
    existing_cols = {t: {c["name"] for c in inspector.get_columns(t)} for t in tables}
    for table, factory in LEGACY_SHIM_COLUMNS:
        column = factory()
        if table in tables and column.name not in existing_cols[table]:
            ops.add_column(table, column)
            existing_cols[table].add(column.name)
            added.append(f"{table}.{column.name}")
    if "password_changed_at" in {a.split(".")[1] for a in added if a.startswith("users.")}:
        conn.execute(sa.text("UPDATE users SET password_changed_at = COALESCE(created_at, CURRENT_TIMESTAMP)"))
    inspector = sa.inspect(conn)
    for index_name, table, column in LEGACY_SHIM_INDEXES:
        if table in tables and column in existing_cols[table]:
            have = {i["name"] for i in inspector.get_indexes(table)}
            if index_name not in have:
                ops.create_index(index_name, table, [column])
    return added


# ----------------------------------------------------------------------------------------------
# Running migrations
# ----------------------------------------------------------------------------------------------

@contextlib.contextmanager
def _migration_engine(engine: Engine) -> Iterator[Engine]:
    """SQLite migrations run on a connection without foreign key enforcement (batch mode recreates tables)."""
    if engine.dialect.name == "sqlite" and _sqlite_lock_path(engine) is not None:
        url = engine.url.render_as_string(hide_password=False)
        mig = app_database.make_engine(url, enforce_foreign_keys=False)
        try:
            yield mig
        finally:
            mig.dispose()
    else:
        yield engine


def run_migrations(engine: Optional[Engine] = None, revision: str = "head") -> None:
    """Bring the database to `revision` (default head). Safe to call from several processes at once."""
    engine = engine or app_database.engine
    import_models()
    with migration_lock(engine):
        with _migration_engine(engine) as mig_engine, mig_engine.connect() as conn:
            if is_legacy_database(conn):
                added = add_legacy_shim_columns(conn)
                conn.commit()
                logger.info(
                    "Existing pre-Alembic database detected; added columns %s and adopting Alembic.",
                    added or "(none needed)",
                )
            cfg = build_config()
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, revision)
            conn.commit()
    logger.info("Database schema is at revision %s.", revision)


def current_revision(engine: Optional[Engine] = None) -> Optional[str]:
    engine = engine or app_database.engine
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def prepare_database(engine: Optional[Engine] = None) -> None:
    """Application startup: migrate, or in PHANTOM_ENV=test create the tables directly (fast)."""
    engine = engine or app_database.engine
    if settings.PHANTOM_ENV.strip().lower() == "test":
        import_models()
        app_database.Base.metadata.create_all(bind=engine)
        return
    run_migrations(engine)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    action = argv[0] if argv else "upgrade"
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    if action == "upgrade":
        run_migrations()
        print(f"Database is at revision {current_revision()}.")
        return 0
    if action == "current":
        print(current_revision() or "(no revision: not migrated)")
        return 0
    if action == "check":
        ok = current_revision() == head_revision()
        print("up to date" if ok else "NOT up to date; run: python -m backend.db_migrate upgrade")
        return 0 if ok else 1
    print("usage: python -m backend.db_migrate [upgrade|current|check]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
