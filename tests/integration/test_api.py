"""Integration-ish API tests with TestClient (no real Redis required for health)."""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    reports = tmp_path / "reports"
    reports.mkdir()
    grype_db = tmp_path / "grype-db"
    auth = tmp_path / "auth"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv("REPORTS_DIR", str(reports))
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(grype_db))
    monkeypatch.setenv("AUTH_TMP_DIR", str(auth))
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/15")
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setenv("ADMIN_USER", "")
    monkeypatch.setenv("ADMIN_PASSWORD", "")
    monkeypatch.setenv(
        "SESSION_SECRET",
        "test-session-secret-please-be-long-enough-32+",
    )
    monkeypatch.setenv(
        "POLICY_FILE",
        str(Path(__file__).resolve().parents[2] / "policies" / "default.yaml"),
    )
    from app.config import get_settings

    get_settings.cache_clear()

    import app.database as database
    from app.database import Base, create_db_engine

    database.engine = create_db_engine(f"sqlite:///{db}")
    database.SessionLocal.configure(bind=database.engine)
    Base.metadata.create_all(bind=database.engine)

    from app.main import create_app

    app = create_app()
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


def test_health(client):
    # redis may fail → degraded ok
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert "status" in body
    assert "grype_db" in body
    assert body["grype_db"] in {"ready", "not_ready", "updating", "error", "unknown"}


def test_create_scan_requires_auth(client):
    r = client.post("/api/v1/scans", json={"image": "alpine:3.20"})
    assert r.status_code == 401


def test_create_scan_with_api_key(client):
    r = client.post(
        "/api/v1/scans",
        json={"image": "alpine:3.20"},
        headers={"X-API-Key": "test-key"},
    )
    # 201 — full success, 503/500 — Redis not reachable in test env, 400 — bad image.
    # The point of this test is to assert auth is bypassed, not to actually enqueue.
    assert r.status_code in (201, 202, 400, 500, 503)


def test_webhook_auth(client, monkeypatch):
    monkeypatch.setenv("HARBOR_WEBHOOK_SECRET", "supersecret")
    from app.config import get_settings

    get_settings.cache_clear()
    r = client.post(
        "/api/v1/webhooks/harbor",
        json={"type": "PUSH_ARTIFACT", "event_data": {}},
        headers={"X-Harbor-Auth": "wrong"},
    )
    assert r.status_code == 401

    r2 = client.post(
        "/api/v1/webhooks/harbor",
        json={"type": "DELETE_ARTIFACT", "event_data": {}},
        headers={"X-Harbor-Auth": "supersecret"},
    )
    assert r2.status_code == 202
    get_settings.cache_clear()


def test_login_logout(client):
    from app.database import session_scope
    from app.models import User
    from app.services.auth import hash_password

    with session_scope() as s:
        s.add(
            User(
                username="alice",
                password_hash=hash_password("alicepass"),
                role="admin",
                is_active=1,
            )
        )
        s.flush()
        alice_id = s.query(User).filter(User.username == "alice").first().id

    r = client.post("/api/v1/auth/login", json={"username": "alice", "password": "alicepass"})
    assert r.status_code == 200
    assert "nss_session" in r.cookies
    cookies = r.cookies

    r2 = client.get("/api/v1/auth/me", cookies=cookies)
    assert r2.status_code == 200
    assert r2.json()["username"] == "alice"
    assert r2.json()["id"] == alice_id

    r3 = client.post("/api/v1/auth/logout", cookies=cookies)
    assert r3.status_code == 200
    r4 = client.get("/api/v1/auth/me", cookies=r3.cookies)
    assert r4.status_code == 401


def test_dashboard_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_dashboard_with_session(client):
    from app.database import session_scope
    from app.models import User
    from app.services.auth import hash_password, issue_session

    with session_scope() as s:
        u = User(
            username="bob",
            password_hash=hash_password("bobpass"),
            role="admin",
            is_active=1,
        )
        s.add(u)
        s.flush()
        bob_id = u.id
    token = issue_session(bob_id)
    r = client.get("/", cookies={"nss_session": token})
    assert r.status_code == 200
    assert "Security Posture" in r.text
