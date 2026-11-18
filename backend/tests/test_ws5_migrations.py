"""Alembic migrations: fresh database, legacy (create_all + ALTER shim) database, drift, concurrency, Postgres."""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from backend import db_migrate
from backend.database import Base, make_engine

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON = sys.executable


def _sqlite_engine(tmp_path, name="m.db"):
    return make_engine(f"sqlite:///{tmp_path / name}")


def _core_tables():
    """Tables defined in backend.models. Models other modules add later are covered by the lead's follow-up migration."""
    from backend import models

    return {m.__table__.name for m in vars(models).values()
            if isinstance(m, type) and issubclass(m, Base) and m is not Base and m.__module__ == models.__name__}


def _drift(engine):
    db_migrate.import_models()
    core = _core_tables()

    def include_object(obj, name, type_, reflected, compare_to):
        table = name if type_ == "table" else getattr(getattr(obj, "table", None), "name", None)
        return table in core

    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True, "include_object": include_object})
        return compare_metadata(ctx, Base.metadata)


# --------------------------------------------------------------------------------------------
# Fresh database
# --------------------------------------------------------------------------------------------

def test_fresh_sqlite_upgrades_to_head_without_drift(tmp_path):
    engine = _sqlite_engine(tmp_path)
    db_migrate.run_migrations(engine)

    assert db_migrate.current_revision(engine) == db_migrate.head_revision()
    tables = set(sa.inspect(engine).get_table_names())
    assert _core_tables() <= tables
    assert _drift(engine) == []


def test_run_migrations_is_idempotent(tmp_path):
    engine = _sqlite_engine(tmp_path)
    db_migrate.run_migrations(engine)
    db_migrate.run_migrations(engine)
    assert db_migrate.current_revision(engine) == db_migrate.head_revision()


def test_there_is_a_single_migration_head():
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(db_migrate.build_config())
    assert len(script.get_heads()) == 1


def test_downgrade_then_upgrade_roundtrip(tmp_path):
    from alembic import command

    engine = _sqlite_engine(tmp_path)
    db_migrate.run_migrations(engine)
    cfg = db_migrate.build_config()
    with engine.connect() as conn:
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "0001")
        conn.commit()
    assert db_migrate.current_revision(engine) == "0001"
    db_migrate.run_migrations(engine)
    assert _drift(engine) == []


# --------------------------------------------------------------------------------------------
# Legacy database: created by create_all + the old SQLite ALTER shim, with data
# --------------------------------------------------------------------------------------------

# The schema as it was before the shim columns existed (oldest supported shape), plus data that the
# new constraints must cope with: duplicate system_configs rows and a user without password_changed_at.
def _legacy_tables():
    """The tables as the old models/create_all made them, before the shim columns existed."""
    md = sa.MetaData()
    pk = dict(primary_key=True, autoincrement=True, index=True)
    sa.Table("users", md,
             sa.Column("user_id", sa.Integer, **pk),
             sa.Column("username", sa.String(50), unique=True, index=True, nullable=False),
             sa.Column("password_hash", sa.String(255), nullable=False),
             sa.Column("role", sa.String(50), nullable=False),
             sa.Column("created_at", sa.DateTime, nullable=False))
    sa.Table("alerts", md,
             sa.Column("alert_id", sa.Integer, **pk),
             sa.Column("rule_id", sa.String(100), index=True, nullable=False),
             sa.Column("source", sa.String(50), nullable=False),
             sa.Column("severity", sa.String(20), index=True, nullable=False),
             sa.Column("status", sa.String(20), index=True, nullable=False),
             sa.Column("raw_payload", sa.JSON, nullable=True),
             sa.Column("created_at", sa.DateTime, nullable=False))
    sa.Table("ioc_artifacts", md,
             sa.Column("artifact_id", sa.Integer, **pk),
             sa.Column("alert_id", sa.Integer, sa.ForeignKey("alerts.alert_id", ondelete="CASCADE"), index=True, nullable=False),
             sa.Column("artifact_type", sa.String(50), nullable=False),
             sa.Column("value", sa.String(500), index=True, nullable=False),
             sa.Column("threat_score", sa.Integer, nullable=False),
             sa.Column("created_at", sa.DateTime, nullable=False))
    sa.Table("containment_actions", md,
             sa.Column("action_id", sa.Integer, **pk),
             sa.Column("alert_id", sa.Integer, sa.ForeignKey("alerts.alert_id", ondelete="CASCADE"), index=True, nullable=False),
             sa.Column("action_type", sa.String(100), nullable=False),
             sa.Column("status", sa.String(50), nullable=False),
             sa.Column("timestamp", sa.DateTime, nullable=False))
    sa.Table("system_configs", md,
             sa.Column("config_id", sa.Integer, **pk),
             sa.Column("category", sa.String(50), index=True, nullable=False),
             sa.Column("key_name", sa.String(100), index=True, nullable=False),
             sa.Column("key_value", sa.String(1000), nullable=False),
             sa.Column("is_secret", sa.Boolean, nullable=False),
             sa.Column("updated_at", sa.DateTime, nullable=False))
    return md


LEGACY_DATA = [
    "INSERT INTO users (username, password_hash, role, created_at) VALUES ('abunemah', 'hash', 'SOC Lead / Admin', '2026-01-02 03:04:05.000000')",
    "INSERT INTO alerts (rule_id, source, severity, status, raw_payload, created_at) VALUES ('5710', 'Wazuh', 'High', 'New', '{\"agent\": \"web-01\"}', '2026-01-02 03:04:05.000000')",
    "INSERT INTO ioc_artifacts (alert_id, artifact_type, value, threat_score, created_at) VALUES (1, 'IP', '203.0.113.9', 80, '2026-01-02 03:04:05.000000')",
    "INSERT INTO containment_actions (alert_id, action_type, status, timestamp) VALUES (1, 'block_ip', 'Executed', '2026-01-02 03:04:05.000000')",
    "INSERT INTO system_configs (category, key_name, key_value, is_secret, updated_at) VALUES ('SIEM', 'wazuh_api_url', 'old', 0, '2026-01-01 00:00:00.000000')",
    "INSERT INTO system_configs (category, key_name, key_value, is_secret, updated_at) VALUES ('SIEM', 'wazuh_api_url', 'newest', 0, '2026-03-01 00:00:00.000000')",
    "INSERT INTO system_configs (category, key_name, key_value, is_secret, updated_at) VALUES ('SIEM', 'wazuh_api_url', 'middle', 0, '2026-02-01 00:00:00.000000')",
    "INSERT INTO system_configs (category, key_name, key_value, is_secret, updated_at) VALUES ('TIP', 'virustotal_api_key', 'k', 1, '2026-01-01 00:00:00.000000')",
]


def _make_legacy_db(tmp_path):
    path = tmp_path / "phantom_soar.db"
    engine = sa.create_engine(f"sqlite:///{path}")
    _legacy_tables().create_all(engine)
    with engine.begin() as conn:
        for statement in LEGACY_DATA:
            conn.execute(sa.text(statement))
    engine.dispose()
    return path


def test_legacy_sqlite_database_is_adopted_with_data_intact(tmp_path):
    path = _make_legacy_db(tmp_path)
    engine = make_engine(f"sqlite:///{path}")
    assert not sa.inspect(engine).has_table("alembic_version")

    db_migrate.run_migrations(engine)

    assert db_migrate.current_revision(engine) == db_migrate.head_revision()
    assert _drift(engine) == []
    inspector = sa.inspect(engine)
    assert _core_tables() <= set(inspector.get_table_names())  # missing tables were created
    user_cols = {c["name"] for c in inspector.get_columns("users")}
    assert {"is_active", "mfa_enabled", "mfa_secret", "api_key_prefix", "failed_login_attempts"} <= user_cols
    assert {"verdict", "enrichment_status", "tip_results"} <= {c["name"] for c in inspector.get_columns("ioc_artifacts")}
    assert {"executed_by", "details"} <= {c["name"] for c in inspector.get_columns("containment_actions")}

    with engine.connect() as conn:
        user = conn.execute(sa.text(
            "SELECT username, is_active, mfa_enabled, must_change_password, failed_login_attempts, "
            "is_service_account, password_changed_at, created_at FROM users")).one()
        assert user.username == "abunemah"
        assert user.is_active == 1 and user.mfa_enabled == 0 and user.must_change_password == 0
        assert user.failed_login_attempts == 0 and user.is_service_account == 0
        assert user.password_changed_at == user.created_at  # back-filled
        assert conn.execute(sa.text("SELECT raw_payload FROM alerts")).scalar() == '{"agent": "web-01"}'
        ioc = conn.execute(sa.text("SELECT value, verdict, enrichment_status FROM ioc_artifacts")).one()
        assert tuple(ioc) == ("203.0.113.9", "Unknown", "pending")
        assert conn.execute(sa.text("SELECT executed_by FROM containment_actions")).scalar() == "System"
        # duplicates removed, newest kept
        rows = conn.execute(sa.text("SELECT key_name, key_value FROM system_configs ORDER BY key_name")).all()
        assert [tuple(r) for r in rows] == [("virustotal_api_key", "k"), ("wazuh_api_url", "newest")]


def test_legacy_database_is_usable_through_the_orm(tmp_path):
    from sqlalchemy.orm import sessionmaker
    from backend.models import Alert, User

    path = _make_legacy_db(tmp_path)
    engine = make_engine(f"sqlite:///{path}")
    db_migrate.run_migrations(engine)
    session = sessionmaker(bind=engine)()
    try:
        user = session.query(User).one()
        assert user.created_at.tzinfo is not None
        assert user.password_changed_at is not None
        assert session.query(Alert).one().ioc_artifacts[0].verdict == "Unknown"
        session.delete(session.query(Alert).one())
        session.commit()  # FK enforcement + cascade on the migrated schema
    finally:
        session.close()


def test_system_config_uniqueness_is_enforced_after_migration(tmp_path):
    engine = _sqlite_engine(tmp_path)
    db_migrate.run_migrations(engine)
    insert = sa.text("INSERT INTO system_configs (category, key_name, key_value, is_secret, updated_at) "
                     "VALUES ('AI', 'model', 'x', 0, '2026-01-01 00:00:00')")
    with engine.begin() as conn:
        conn.execute(insert)
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:
            conn.execute(insert)


# --------------------------------------------------------------------------------------------
# Concurrent start-up
# --------------------------------------------------------------------------------------------

def test_concurrent_processes_do_not_race(tmp_path):
    db = tmp_path / "race.db"
    script = textwrap.dedent(f"""
        import os, sys
        os.environ["PHANTOM_ENV"] = "test"
        os.environ["REPORTS_DIR"] = {str(tmp_path / 'reports')!r}
        os.environ["DATABASE_URL"] = "sqlite:///{db}"
        from backend import db_migrate
        from backend.database import make_engine
        db_migrate.run_migrations(make_engine("sqlite:///{db}"))
        print("ok", db_migrate.current_revision(make_engine("sqlite:///{db}")))
    """)
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    procs = [subprocess.Popen([PYTHON, "-c", script], cwd=REPO_ROOT, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    results = [p.communicate(timeout=120) + (p.returncode,) for p in procs]
    for out, err, code in results:
        assert code == 0, err
        assert out.strip().startswith("ok ")
    engine = make_engine(f"sqlite:///{db}")
    assert db_migrate.current_revision(engine) == db_migrate.head_revision()
    assert _drift(engine) == []


def test_migration_lock_serialises_holders(tmp_path):
    import threading
    import time

    engine = _sqlite_engine(tmp_path)
    events = []

    def worker(name):
        with db_migrate.migration_lock(engine):
            events.append(f"{name}-in")
            time.sleep(0.4)
            events.append(f"{name}-out")

    threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # never interleaved: each "in" is immediately followed by the same worker's "out"
    assert events[0].endswith("-in") and events[1] == events[0].replace("-in", "-out")


# --------------------------------------------------------------------------------------------
# Start-up behaviour
# --------------------------------------------------------------------------------------------

def test_prepare_database_in_test_env_uses_create_all(tmp_path):
    engine = _sqlite_engine(tmp_path, "fast.db")
    db_migrate.prepare_database(engine)  # PHANTOM_ENV=test in the suite
    inspector = sa.inspect(engine)
    assert _core_tables() <= set(inspector.get_table_names())
    assert not inspector.has_table("alembic_version")


def test_prepare_database_outside_test_env_runs_migrations(tmp_path, monkeypatch):
    monkeypatch.setattr(db_migrate.settings, "PHANTOM_ENV", "production")
    engine = _sqlite_engine(tmp_path, "prod.db")
    db_migrate.prepare_database(engine)
    assert db_migrate.current_revision(engine) == db_migrate.head_revision()


def test_cli_check_reports_state(tmp_path, capsys, monkeypatch):
    engine = _sqlite_engine(tmp_path, "cli.db")
    monkeypatch.setattr(db_migrate.app_database, "engine", engine)
    assert db_migrate.main(["check"]) == 1
    assert db_migrate.main(["upgrade"]) == 0
    assert db_migrate.main(["check"]) == 0
    assert db_migrate.main(["bogus"]) == 2


def test_alembic_cli_works_from_repo_root(tmp_path):
    db = tmp_path / "cli_alembic.db"
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), DATABASE_URL=f"sqlite:///{db}")
    out = subprocess.run([PYTHON, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"],
                         cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    out = subprocess.run([PYTHON, "-m", "alembic", "-c", "backend/alembic.ini", "check"],
                         cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr + out.stdout


# --------------------------------------------------------------------------------------------
# Postgres (runs only when PHANTOM_TEST_POSTGRES_URL points at an empty, throwaway database)
# --------------------------------------------------------------------------------------------

POSTGRES_URL = os.environ.get("PHANTOM_TEST_POSTGRES_URL")
needs_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="set PHANTOM_TEST_POSTGRES_URL=postgresql+psycopg2://user@host:port/throwaway_db to run (see backend/alembic/README.md)",
)


@pytest.fixture
def pg_engine():
    engine = make_engine(POSTGRES_URL)
    with engine.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA public CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA public"))
    yield engine
    with engine.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA public CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA public"))
    engine.dispose()


@needs_postgres
def test_postgres_fresh_upgrade_and_no_drift(pg_engine):
    db_migrate.run_migrations(pg_engine)
    assert db_migrate.current_revision(pg_engine) == db_migrate.head_revision()
    assert _drift(pg_engine) == []
    cols = {c["name"]: c for c in sa.inspect(pg_engine).get_columns("alerts")}
    assert cols["created_at"]["type"].timezone is True


@needs_postgres
def test_postgres_legacy_database_is_converted(pg_engine):
    from datetime import timezone
    """A database made by the old create_all (naive timestamps, 1000-char key_value, no unique key)."""
    db_migrate.run_migrations(pg_engine, "0001")
    with pg_engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE alembic_version"))  # now looks like a pre-Alembic database
        conn.execute(sa.text(
            "INSERT INTO users (username, password_hash, role, must_change_password, is_active, mfa_enabled, "
            "password_changed_at, compromised_reset_required, failed_login_attempts, is_service_account, created_at) "
            "VALUES ('abunemah', 'h', 'SOC Lead / Admin', false, true, false, '2026-01-02 03:04:05', false, 0, false, '2026-01-02 03:04:05')"))
        for value, when in (("old", "2026-01-01"), ("newest", "2026-03-01")):
            conn.execute(sa.text(
                "INSERT INTO system_configs (category, key_name, key_value, is_secret, updated_at) "
                f"VALUES ('SIEM', 'wazuh_api_url', '{value}', false, '{when}')"))

        # columns the old ALTER shim used to add are missing from a really old database
        conn.execute(sa.text("ALTER TABLE users DROP COLUMN is_active, DROP COLUMN api_key_prefix"))
        conn.execute(sa.text("ALTER TABLE ioc_artifacts DROP COLUMN verdict"))

    db_migrate.run_migrations(pg_engine)

    assert db_migrate.current_revision(pg_engine) == db_migrate.head_revision()
    assert _drift(pg_engine) == []
    with pg_engine.connect() as conn:
        assert conn.execute(sa.text("SELECT is_active FROM users")).scalar() is True
        assert conn.execute(sa.text("SELECT key_value FROM system_configs")).scalars().all() == ["newest"]
        created = conn.execute(sa.text("SELECT created_at FROM users")).scalar()
        assert created.utcoffset() is not None
        assert created.astimezone(timezone.utc).isoformat().startswith("2026-01-02T03:04:05")  # reinterpreted as UTC, not shifted


@needs_postgres
def test_postgres_models_roundtrip_and_cascade(pg_engine):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy.orm import sessionmaker
    from backend.models import Alert, Playbook, PlaybookExecution, SystemConfig, User

    db_migrate.run_migrations(pg_engine)
    session = sessionmaker(bind=pg_engine)()
    plus_two = timezone(timedelta(hours=2))
    session.add(User(username="u", password_hash="h", mfa_secret="x" * 255,
                     locked_until=datetime(2026, 5, 1, 12, 0, tzinfo=plus_two)))
    session.add(SystemConfig(category="AI", key_name="k", key_value="v" * 5000))
    alert = Alert(rule_id="1", severity="High")
    playbook = Playbook(name="p", target_threat="t", workflow_logic="{}")
    session.add_all([alert, playbook])
    session.flush()
    session.add(PlaybookExecution(alert_id=alert.alert_id, playbook_id=playbook.playbook_id))
    session.commit()
    user = session.query(User).one()
    assert user.locked_until == datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    assert len(user.mfa_secret) == 255
    assert len(session.query(SystemConfig).one().key_value) == 5000
    session.delete(playbook)
    session.commit()
    execution = session.query(PlaybookExecution).one()
    assert execution.playbook_id is None
    session.delete(alert)
    session.commit()
    assert session.query(PlaybookExecution).count() == 0
    session.close()


@needs_postgres
def test_postgres_concurrent_processes_do_not_race(pg_engine):
    script = textwrap.dedent(f"""
        import os
        os.environ["PHANTOM_ENV"] = "test"
        os.environ["DATABASE_URL"] = {POSTGRES_URL!r}
        from backend import db_migrate
        from backend.database import make_engine
        engine = make_engine({POSTGRES_URL!r})
        db_migrate.run_migrations(engine)
        print("ok", db_migrate.current_revision(engine))
    """)
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    procs = [subprocess.Popen([PYTHON, "-c", script], cwd=REPO_ROOT, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    for p in procs:
        out, err = p.communicate(timeout=180)
        assert p.returncode == 0, err
        assert out.strip().startswith("ok ")
    assert db_migrate.current_revision(pg_engine) == db_migrate.head_revision()
