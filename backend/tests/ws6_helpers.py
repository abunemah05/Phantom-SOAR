"""Shared helpers and fixtures for the WS6 security tests."""
import os

import pytest
from cryptography.fernet import Fernet  # noqa: F401
from starlette.requests import Request
from starlette.testclient import TestClient

from backend import crypto, ratelimit
from backend.security import create_access_token

ADMIN_PASSWORD = os.environ["PHANTOM_BOOTSTRAP_ADMIN_PASSWORD"]
STRONG_PASSWORD = "Correct-Horse-Battery-Staple-26"


def admin_name() -> str:
    from backend.routers.auth import get_bootstrap_admin_username
    return get_bootstrap_admin_username()


def bearer(username: str, **claims) -> dict:
    return {"Authorization": f"Bearer {create_access_token({'sub': username, **claims})}"}


@pytest.fixture
def admin_h(client):
    return bearer(admin_name())


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    ratelimit.reset_all()
    ratelimit.limiter._redis = None
    ratelimit.limiter._redis_down_until = 0.0
    monkeypatch.setenv("PHANTOM_LOGIN_DELAY_SECONDS", "0")  # no real sleeping in tests
    crypto.reset_cache()
    yield
    ratelimit.reset_all()
    crypto.reset_cache()


def make_user(client, admin_h, username, role="SOC Analyst"):
    for u in client.get("/api/users", headers=admin_h).json():
        if u["username"] == username:
            client.delete(f"/api/users/{u['user_id']}", headers=admin_h)
    res = client.post("/api/users", json={"username": username, "role": role}, headers=admin_h)
    assert res.status_code == 201, res.text
    return res.json()


def client_from(ip: str) -> TestClient:
    from backend.main import app
    return TestClient(app, client=(ip, 50000))


def make_request(peer, xff=None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 1234)})


class use_keys:
    """Temporarily set PHANTOM_ENCRYPTION_KEY(S) and reload the crypto key cache."""

    def __init__(self, single=None, many=None):
        self.env = {"PHANTOM_ENCRYPTION_KEY": single, "PHANTOM_ENCRYPTION_KEYS": many}

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self.env}
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        crypto.reset_cache()

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        crypto.reset_cache()




@pytest.fixture(scope="session", autouse=True)
def _mount_ingest_router():
    """Mount /ingest-tokens on the app if main.py does not include it yet (the lead wires it in main.py)."""
    from backend.main import app
    from backend.routers.ingest_tokens import router

    if not any(getattr(r, "path", "").startswith("/api/ingest-tokens") for r in app.routes):
        app.include_router(router, prefix="/api")
