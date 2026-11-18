"""Alembic environment for Phantom SOAR (SQLite and Postgres).

The URL comes from backend.config / backend.database (DATABASE_URL, including the
postgres:// normalisation), never from alembic.ini. The programmatic entry point
(backend.db_migrate) passes an open connection in config.attributes["connection"].
"""
from logging.config import fileConfig

from alembic import context

from backend import database as app_database

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Model modules are listed in backend/db_migrate.py (MODEL_MODULES).
from backend.db_migrate import import_models  # noqa: E402

import_models()

target_metadata = app_database.Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or app_database.DATABASE_URL


def _configure(**kwargs):
    context.configure(
        target_metadata=target_metadata,
        compare_type=True,
        # SQLite cannot ALTER most things in place; batch mode recreates the table instead.
        # https://alembic.sqlalchemy.org/en/latest/batch.html
        render_as_batch=True,
        **kwargs,
    )


def run_migrations_offline() -> None:
    _configure(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def _run(connection) -> None:
    _configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        connection.commit()
        return
    engine = app_database.make_engine(_url(), enforce_foreign_keys=False)
    try:
        with engine.connect() as conn:
            _run(conn)
            conn.commit()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
