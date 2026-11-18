"""Model/database fixes (UTC datetimes, FK enforcement, uniqueness, pool) and main.py start-up behaviour."""
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from backend.database import Base, UTCDateTime, make_engine, session_scope

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def engine(tmp_path):
    from backend import models  # noqa: F401  (register tables)

    eng = make_engine(f"sqlite:///{tmp_path / 'models.db'}")
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


# ---------------------------------------------------------------- UTCDateTime

def test_utc_datetime_returns_aware_utc_and_converts_offsets(session, engine):
    from backend.models import User

    plus_three = timezone(timedelta(hours=3))
    session.add(User(username="a", password_hash="h", locked_until=datetime(2026, 5, 1, 12, 0, tzinfo=plus_three)))
    session.commit()
    session.expire_all()
    user = session.query(User).one()
    assert user.locked_until == datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)
    assert user.locked_until.tzinfo is not None and user.locked_until.utcoffset() == timedelta(0)
    assert user.created_at.tzinfo is not None
    # stored as the UTC wall clock
    raw = session.execute(sa.text("SELECT locked_until FROM users")).scalar()
    assert raw.startswith("2026-05-01 09:00:00")


def test_utc_datetime_treats_naive_input_as_utc_and_keeps_none(session):
    from backend.models import User

    session.add(User(username="n", password_hash="h", locked_until=datetime(2026, 5, 1, 9, 0)))
    session.add(User(username="m", password_hash="h"))
    session.commit()
    session.expire_all()
    assert session.query(User).filter_by(username="n").one().locked_until == datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)
    assert session.query(User).filter_by(username="m").one().locked_until is None


def test_utc_datetime_comparisons_work_with_naive_and_aware_filters(session):
    from backend.models import User

    session.add(User(username="c", password_hash="h", locked_until=datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)))
    session.commit()
    aware = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    naive = aware.replace(tzinfo=None)
    assert session.query(User).filter(User.locked_until < aware).count() == 1
    assert session.query(User).filter(User.locked_until < naive).count() == 1  # old-style naive callers keep working


def test_utc_datetime_rejects_non_datetime():
    with pytest.raises(TypeError):
        UTCDateTime().process_bind_param("2026-01-01", None)


def test_no_model_column_uses_a_naive_datetime():
    from backend import models

    core = {m.__table__.name for m in vars(models).values()
            if isinstance(m, type) and issubclass(m, Base) and m is not Base and m.__module__ == models.__name__}
    assert len(core) >= 11
    for name in core:
        for column in Base.metadata.tables[name].columns:
            if isinstance(column.type, sa.DateTime):
                assert isinstance(column.type, UTCDateTime), f"{name}.{column.name} is a naive DateTime"


# ---------------------------------------------------------------- constraints

def test_sqlite_connections_enforce_foreign_keys(engine):
    with engine.connect() as conn:
        assert conn.execute(sa.text("PRAGMA foreign_keys")).scalar() == 1


def test_orphan_rows_are_rejected_and_cascades_run_in_the_database(engine):
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:
            conn.execute(sa.text(
                "INSERT INTO ioc_artifacts (alert_id, artifact_type, value, threat_score, verdict, enrichment_status, created_at) "
                "VALUES (999, 'IP', '1.2.3.4', 0, 'Unknown', 'pending', '2026-01-01 00:00:00')"))
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO alerts (alert_id, rule_id, source, severity, status, created_at) "
                             "VALUES (1, 'r', 'Wazuh', 'High', 'New', '2026-01-01 00:00:00')"))
        conn.execute(sa.text(
            "INSERT INTO ioc_artifacts (alert_id, artifact_type, value, threat_score, verdict, enrichment_status, created_at) "
            "VALUES (1, 'IP', '1.2.3.4', 0, 'Unknown', 'pending', '2026-01-01 00:00:00')"))
        conn.execute(sa.text("DELETE FROM alerts WHERE alert_id = 1"))  # raw SQL: only the FK cascade can clean up
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT COUNT(*) FROM ioc_artifacts")).scalar() == 0


def test_system_config_category_and_key_are_unique(session):
    from backend.models import SystemConfig

    session.add(SystemConfig(category="AI", key_name="model", key_value="a"))
    session.commit()
    session.add(SystemConfig(category="AI", key_name="model", key_value="b"))
    with pytest.raises(sa.exc.IntegrityError):
        session.commit()
    session.rollback()
    session.add(SystemConfig(category="SIEM", key_name="model", key_value="b"))  # same key, other category is fine
    session.commit()


def test_encrypted_sized_values_fit(session):
    from backend.models import SystemConfig, User

    session.add(SystemConfig(category="AI", key_name="k", key_value="enc:" + "x" * 4000))
    session.add(User(username="mfa", password_hash="h", mfa_secret="y" * 255))
    session.commit()
    assert len(session.query(SystemConfig).one().key_value) == 4004
    assert SystemConfig.__table__.c.key_value.type.__class__ is sa.Text
    assert User.__table__.c.mfa_secret.type.length == 255


def test_deleting_a_playbook_keeps_its_executions_with_null_playbook(session):
    from backend.models import Alert, Playbook, PlaybookExecution

    alert = Alert(rule_id="1", severity="High")
    playbook = Playbook(name="p", target_threat="t", workflow_logic="{}")
    session.add_all([alert, playbook])
    session.flush()
    session.add(PlaybookExecution(alert_id=alert.alert_id, playbook_id=playbook.playbook_id))
    session.commit()
    session.delete(playbook)
    session.commit()
    kept = session.query(PlaybookExecution).one()
    assert kept.playbook_id is None
    session.delete(alert)
    session.commit()
    assert session.query(PlaybookExecution).count() == 0


# ---------------------------------------------------------------- database.py

def test_postgres_pool_settings_defaults_and_overrides(monkeypatch):
    url = "postgresql+psycopg2://u:p@127.0.0.1:1/x"  # never connected: engines are lazy
    eng = make_engine(url)
    assert eng.pool.size() == 10 and eng.pool._max_overflow == 20
    assert eng.pool._recycle == 1800 and eng.pool._pre_ping is True
    monkeypatch.setenv("PHANTOM_DB_POOL_SIZE", "3")
    monkeypatch.setenv("PHANTOM_DB_MAX_OVERFLOW", "oops")  # invalid -> default
    eng = make_engine(url)
    assert eng.pool.size() == 3 and eng.pool._max_overflow == 20


def test_session_scope_commits_and_rolls_back(monkeypatch, engine):
    from backend import database
    from backend.models import Playbook

    monkeypatch.setattr(database, "SessionLocal", sessionmaker(bind=engine))
    with session_scope() as db:
        db.add(Playbook(name="ok", target_threat="t", workflow_logic="{}"))
    with pytest.raises(RuntimeError):
        with session_scope() as db:
            db.add(Playbook(name="lost", target_threat="t", workflow_logic="{}"))
            db.flush()
            raise RuntimeError("boom")
    with sessionmaker(bind=engine)() as check:
        assert [p.name for p in check.query(Playbook)] == ["ok"]


def test_sqlite_fallback_rule_still_refuses_unreachable_database():
    script = textwrap.dedent("""
        import os
        os.environ["DATABASE_URL"] = "postgresql://u:p@127.0.0.1:1/x"
        os.environ.pop("PHANTOM_ALLOW_SQLITE_FALLBACK", None)
        try:
            import backend.database
        except RuntimeError as e:
            print("refused", "u:***" in str(e) or "p@" not in str(e))
    """)
    out = subprocess.run([sys.executable, "-c", script], cwd=REPO_ROOT, capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=str(REPO_ROOT), PHANTOM_ENV="test"), timeout=60)
    assert out.stdout.strip() == "refused True", out.stderr


# ---------------------------------------------------------------- main.py

def _run_app_script(body: str, tmp_path, **env):
    script = textwrap.dedent("""
        import json, os
        from fastapi.testclient import TestClient
    """) + textwrap.dedent(body)
    full_env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), DATABASE_URL=f"sqlite:///{tmp_path / 'app.db'}",
                    REPORTS_DIR=str(tmp_path / "reports"), PHANTOM_JWT_SECRET="x" * 48,
                    PHANTOM_BOOTSTRAP_ADMIN_PASSWORD="Test-Admin-Passphrase-2026", PHANTOM_ENV="test")
    full_env.pop("PHANTOM_ENABLE_DOCS", None)
    full_env.pop("PHANTOM_BEHIND_TLS", None)
    full_env.update(env)
    out = subprocess.run([sys.executable, "-c", script], cwd=REPO_ROOT, env=full_env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_importing_main_has_no_database_side_effects(tmp_path):
    result = _run_app_script("""
        import backend.main
        import sqlalchemy as sa
        from backend.database import engine
        print(json.dumps(sa.inspect(engine).get_table_names()))
    """, tmp_path)
    assert result == []


def test_bootstrap_runs_once_even_with_repeated_lifespans(monkeypatch):
    import backend.main as main

    calls = {"prepare": 0, "seed": 0}
    monkeypatch.setattr(main, "_bootstrapped", False)
    monkeypatch.setattr(main, "prepare_database", lambda engine: calls.__setitem__("prepare", calls["prepare"] + 1))
    monkeypatch.setattr(main, "init_system_defaults", lambda: calls.__setitem__("seed", calls["seed"] + 1))
    from fastapi.testclient import TestClient

    for _ in range(2):
        with TestClient(main.app):
            pass
    main.bootstrap_database()
    assert calls == {"prepare": 1, "seed": 1}


def test_lifespan_creates_schema_and_seeds_on_a_fresh_database(tmp_path):
    result = _run_app_script("""
        from backend.main import app
        import sqlalchemy as sa
        from backend.database import engine
        with TestClient(app) as c:
            health = c.get("/api/health")
        names = sa.inspect(engine).get_table_names()
        with engine.connect() as conn:
            users = conn.execute(sa.text("SELECT COUNT(*) FROM users")).scalar()
            playbooks = conn.execute(sa.text("SELECT COUNT(*) FROM playbooks")).scalar()
        print(json.dumps({"status": health.status_code, "keys": sorted(health.json()), "has_users": "users" in names,
                          "users": users, "playbooks": playbooks}))
    """, tmp_path)
    assert result["status"] == 200
    assert result["keys"] == ["architecture", "database", "status", "version"]
    assert result["has_users"] and result["users"] == 1 and result["playbooks"] > 0


def test_lifespan_runs_alembic_outside_test_env(tmp_path):
    result = _run_app_script("""
        from backend.main import app
        from backend import db_migrate
        with TestClient(app) as c:
            c.get("/api/health")
        print(json.dumps({"rev": db_migrate.current_revision(), "head": db_migrate.head_revision()}))
    """, tmp_path, PHANTOM_ENV="development")
    assert result["rev"] == result["head"]


@pytest.mark.parametrize("env,enable,expected", [
    ("production", None, False),
    ("production", "true", True),
    ("production", "false", False),
    ("development", None, True),
    ("development", "false", False),
    ("test", None, True),
])
def test_docs_enabled_matrix(monkeypatch, env, enable, expected):
    import backend.main as main

    monkeypatch.setattr(main.settings, "PHANTOM_ENV", env)
    if enable is None:
        monkeypatch.delenv("PHANTOM_ENABLE_DOCS", raising=False)
    else:
        monkeypatch.setenv("PHANTOM_ENABLE_DOCS", enable)
    assert main.docs_enabled() is expected


@pytest.mark.parametrize("env,enable,status", [
    ("production", None, 404),
    ("production", "true", 200),
    ("development", None, 200),
])
def test_docs_routes_hidden_in_production(tmp_path, env, enable, status):
    extra = {"PHANTOM_ENV": env}
    if enable:
        extra["PHANTOM_ENABLE_DOCS"] = enable
    result = _run_app_script("""
        from backend.main import app
        c = TestClient(app)   # no lifespan: only routing is exercised
        print(json.dumps([c.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json")]))
    """, tmp_path, **extra)
    assert result == [status] * 3


def test_hsts_only_when_behind_tls(client, monkeypatch):
    monkeypatch.delenv("PHANTOM_BEHIND_TLS", raising=False)
    assert "strict-transport-security" not in client.get("/api/health").headers
    monkeypatch.setenv("PHANTOM_BEHIND_TLS", "true")
    header = client.get("/api/health").headers["strict-transport-security"]
    assert header.startswith("max-age=") and "includeSubDomains" in header
    monkeypatch.setenv("PHANTOM_BEHIND_TLS", "false")
    assert "strict-transport-security" not in client.get("/api/health").headers


def test_health_keeps_its_response_keys(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert set(response.json()) == {"status", "database", "architecture", "version"}


def test_main_has_no_sqlite_alter_shim_left():
    import backend.main as main

    assert not hasattr(main, "ensure_sqlite_migrations")
    assert "ALTER TABLE" not in Path(main.__file__).read_text()


# ---------------------------------------------------------------- requirements

def test_requirements_declare_alembic_and_cryptography_and_lock_pins_them():
    backend = REPO_ROOT / "backend"
    declared = (backend / "requirements.txt").read_text().lower()
    assert "alembic>=" in declared and "cryptography>=" in declared
    lock = (backend / "requirements.lock").read_text().lower().splitlines()
    pinned = {line.split("==")[0] for line in lock if "==" in line and not line.startswith("#")}
    for name in ("alembic", "cryptography", "sqlalchemy", "fastapi", "psycopg2-binary"):
        assert name in pinned, name
