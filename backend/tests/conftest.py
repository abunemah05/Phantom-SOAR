"""Shared test setup.

Environment variables must be set before any `backend` module is imported,
because settings are read at import time. Every test session gets its own
throwaway SQLite database and reports directory so the developer database
is never touched.
"""
import os
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="phantom_soar_test_")

os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_TMP_DIR, 'test.db')}"
os.environ["REPORTS_DIR"] = os.path.join(_TMP_DIR, "reports")
os.environ["CELERY_BROKER_URL"] = "redis://127.0.0.1:1/0"  # unreachable -> runner executes synchronously
os.environ["PHANTOM_ENV"] = "test"
os.environ["PHANTOM_JWT_SECRET"] = "test-only-jwt-secret-not-for-production-use-0123456789"
os.environ["PHANTOM_BOOTSTRAP_ADMIN_PASSWORD"] = "Test-Admin-Passphrase-2026"
os.environ["PHANTOM_INGEST_TOKEN"] = "test-ingest-token"
os.environ["PHANTOM_SIMULATION_MODE"] = "true"

# Never let tests reach real threat-intel or response APIs.
for _key in (
    "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "ALIENVAULT_OTX_API_KEY", "THREATFOX_API_KEY",
    "NVD_API_KEY", "WAZUH_API_URL", "WAZUH_API_PASSWORD", "OKTA_DOMAIN", "OKTA_API_TOKEN",
    "JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_WEBHOOK_URL", "SLACK_WEBHOOK_URL",
):
    os.environ.pop(_key, None)

import pytest  # noqa: E402

ADMIN_USERNAME = "abunemah"
ADMIN_PASSWORD = os.environ["PHANTOM_BOOTSTRAP_ADMIN_PASSWORD"]
INGEST_HEADERS = {"X-Phantom-Ingest-Token": os.environ["PHANTOM_INGEST_TOKEN"]}


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient
    from backend.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_headers():
    """Bearer header for the bootstrap admin, minted directly so it does not depend on the login flow."""
    from backend.main import app  # noqa: F401  (ensures the bootstrap admin exists)
    from backend.security import create_access_token

    token = create_access_token({"sub": ADMIN_USERNAME})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def ingest_headers():
    return dict(INGEST_HEADERS)
