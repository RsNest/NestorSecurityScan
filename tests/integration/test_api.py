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


def test_create_scan_requires_api_key(client):
    r = client.post("/api/v1/scans", json={"image": "alpine:3.20"})
    assert r.status_code == 401


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
