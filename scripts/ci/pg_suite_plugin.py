"""pytest plugin that runs the whole backend suite on Postgres (used by CI, not by the application).

backend/tests/conftest.py points DATABASE_URL at a throwaway SQLite file. This plugin runs right after
conftest has been imported and before any test module imports the application, and replaces that value
with PHANTOM_TEST_DATABASE_URL, which must name an EMPTY, THROWAWAY database (tables are created in it and
the suite writes a lot of data). Enable it with:

    PHANTOM_TEST_DATABASE_URL=postgresql+psycopg2://user:pw@localhost:5432/suite \
    PYTHONPATH=scripts/ci python -m pytest backend/tests -p pg_suite_plugin
"""
import os


def pytest_sessionstart(session):
    url = os.environ.get("PHANTOM_TEST_DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("pg_suite_plugin needs PHANTOM_TEST_DATABASE_URL (an empty throwaway Postgres database)")
    if "postgres" not in url:
        raise RuntimeError("PHANTOM_TEST_DATABASE_URL must be a postgresql:// URL")
    os.environ["DATABASE_URL"] = url
