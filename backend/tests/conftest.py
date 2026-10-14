"""Test configuration. Uses a temporary SQLite database and mock providers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Must be set before importing the application.
_TMP = Path(tempfile.mkdtemp(prefix="phishshield-test-"))
os.environ.setdefault("ENVIRONMENT", "test")
os.environ["DATABASE_URL"] = f"sqlite+pysqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["TOKEN_ENCRYPTION_KEY"] = "boRO9wsEaiQ-_fVwybk4krufouhuKcYFADwbR_DEtqA="
os.environ["MOCK_PROVIDERS"] = "1"
os.environ["ML_ENABLED"] = "0"
os.environ["COOKIE_SECURE"] = "0"
os.environ["UPLOAD_DIR"] = str(_TMP / "uploads")
os.environ["QUARANTINE_DIR"] = str(_TMP / "quarantine")
os.environ["EVIDENCE_DIR"] = str(_TMP / "evidence")
os.environ["RATE_LIMIT_PER_MINUTE"] = "10000"
os.environ["LOGIN_RATE_LIMIT_PER_MINUTE"] = "10000"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _create_schema():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db():
    from app.core.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    from app.api.v1 import auth

    auth._login_limiter.reset()
    yield


@pytest.fixture()
def owner(client):
    """Bootstrap an owner and return (client, csrf)."""
    r = client.get("/api/v1/auth/bootstrap-status")
    if r.json().get("needs_bootstrap"):
        resp = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "tenant_name": "Acme Security",
                "email": "owner@acme-security.com",
                "full_name": "Owner",
                "password": "Str0ng-Passphrase-1",
            },
        )
        assert resp.status_code == 201, resp.text
        csrf = resp.json()["csrf_token"]
    else:
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "owner@acme-security.com", "password": "Str0ng-Passphrase-1"},
        )
        assert resp.status_code == 200, resp.text
        csrf = resp.json()["csrf_token"]
    return client, csrf


def auth_headers(csrf: str) -> dict:
    return {"X-CSRF-Token": csrf}
