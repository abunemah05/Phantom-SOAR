# Database migrations (Alembic)

Schema changes are made with Alembic. The URL always comes from `DATABASE_URL` (via `backend/config.py`),
never from `alembic.ini`. Run every command from the **repository root** (or `/app` in the Docker image):

    alembic -c backend/alembic.ini upgrade head        # apply migrations
    alembic -c backend/alembic.ini current             # show the applied revision
    alembic -c backend/alembic.ini check               # fail if the models differ from the migrations
    python -m backend.db_migrate upgrade|current|check # same, through the application's own helper

The API runs the same upgrade at start-up (inside the FastAPI lifespan) under a lock (Postgres advisory
lock, or a `<db>.migrate.lock` file for SQLite), so several processes starting together do not race.
With `PHANTOM_ENV=test` the tables are created directly with `create_all` for speed.

## Revisions

| Revision | Content |
|---|---|
| `0001` | Baseline: the schema as it was before Alembic (naive DateTime columns). Creates only tables that do not exist yet, so it is also safe on databases created by the old `create_all`. |
| `0002` | `system_configs` de-duplication plus unique `(category, key_name)`; `users.mfa_secret` String(255); `system_configs.key_value` Text; Postgres naive timestamps become `timestamptz`. |

Databases that predate Alembic (tables, no `alembic_version`) are detected by `backend/db_migrate.py`: it adds the
columns the removed SQLite ALTER shim used to add (on SQLite and Postgres), then upgrades to head. Data is kept.

## Second migration after the other work streams are merged (lead)

1. Add each new model module to `MODEL_MODULES` in `backend/db_migrate.py` (single list used by Alembic, by
   `create_all` in test mode and by autogenerate). New timestamp columns must use
   `from backend.database import UTCDateTime`, not `DateTime`. Name every constraint explicitly
   (`UniqueConstraint(..., name="uq_...")`, `ForeignKey(..., name="fk_...")`) so SQLite batch mode can drop it later.
2. Generate against an empty scratch database (never against production), at head:

       rm -f /tmp/gen.db
       DATABASE_URL=sqlite:////tmp/gen.db PHANTOM_ENV=development REPORTS_DIR=/tmp/gen_reports \
         alembic -c backend/alembic.ini upgrade head
       DATABASE_URL=sqlite:////tmp/gen.db PHANTOM_ENV=development REPORTS_DIR=/tmp/gen_reports \
         alembic -c backend/alembic.ini revision --autogenerate --rev-id 0003 -m "agents ingest tokens ai settings"

3. Review the generated file by hand (autogenerate cannot see renames, data fixes or server defaults), then check it on
   SQLite and Postgres: `alembic -c backend/alembic.ini check` must report no new upgrade operations afterwards.
   `backend/tests/test_ws5_migrations.py::test_*drift*` style checks compare only `backend.models`; extend `_core_tables()`
   there (or add a new test) to cover the new tables.

## Testing against Postgres

The Postgres tests in `backend/tests/test_ws5_migrations.py` run when `PHANTOM_TEST_POSTGRES_URL` points at an
empty throwaway database (the test **drops the `public` schema** in it). Example, as a non-root user:

    initdb -D /tmp/pg/data -A trust -U postgres
    pg_ctl -D /tmp/pg/data -o "-p 54329 -k /tmp/pg -c listen_addresses=127.0.0.1" -l /tmp/pg/log -w start
    createdb -h 127.0.0.1 -p 54329 -U postgres phantom_test
    PHANTOM_TEST_POSTGRES_URL=postgresql+psycopg2://postgres@127.0.0.1:54329/phantom_test pytest backend/tests/test_ws5_migrations.py

## Notes

* The directory is named `alembic/` as required but has no `__init__.py`, so `import alembic` still resolves to the
  installed library.
* SQLite migrations run with foreign-key enforcement off (batch mode recreates tables); the application's own
  connections have `PRAGMA foreign_keys=ON`.
* `0002` downgrade narrows `key_value` back to 1000 characters; longer values would be truncated or rejected.
