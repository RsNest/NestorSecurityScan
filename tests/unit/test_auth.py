"""Tests for auth (password hashing, sessions, RBAC)."""

import pytest
from fastapi.testclient import TestClient

from app.services.auth import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    CurrentUser,
    hash_password,
    issue_session,
    read_session,
    verify_password,
)


def test_password_hash_and_verify():
    h = hash_password("hunter2hunter")
    assert h != "hunter2hunter"
    assert verify_password("hunter2hunter", h)
    assert not verify_password("wrong", h)
    assert not verify_password("", h)
    assert not verify_password("hunter2hunter", "")


def test_session_roundtrip():
    token = issue_session(42)
    assert read_session(token) == 42


def test_session_invalid_returns_none():
    assert read_session("not-a-valid-token") is None
    assert read_session("") is None
    assert read_session(None) is None


def test_current_user_role_ranking():
    admin = CurrentUser.__new__(CurrentUser)
    admin.id, admin.username, admin.role = 1, "a", ROLE_ADMIN
    operator = CurrentUser.__new__(CurrentUser)
    operator.id, operator.username, operator.role = 2, "o", ROLE_OPERATOR
    viewer = CurrentUser.__new__(CurrentUser)
    viewer.id, viewer.username, viewer.role = 3, "v", ROLE_VIEWER

    assert admin.has_role(ROLE_VIEWER)
    assert admin.has_role(ROLE_OPERATOR)
    assert admin.has_role(ROLE_ADMIN)
    assert operator.has_role(ROLE_VIEWER)
    assert not operator.has_role(ROLE_ADMIN)
    assert not viewer.has_role(ROLE_OPERATOR)


def test_bootstrap_admin_creates_only_if_empty(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv("ADMIN_USER", "root")
    monkeypatch.setenv("ADMIN_PASSWORD", "rootroot")
    monkeypatch.setenv("SESSION_SECRET", "x" * 40)
    from app.config import get_settings
    get_settings.cache_clear()

    from app.database import Base, create_db_engine, session_scope
    from app.models import User
    from app.services.auth import ensure_bootstrap_admin, verify_password

    engine = create_db_engine(f"sqlite:///{db}")
    Base.metadata.create_all(bind=engine)
    import app.database as db_mod

    db_mod.engine = engine
    db_mod.SessionLocal.configure(bind=engine)

    ensure_bootstrap_admin()
    with session_scope() as s:
        u = s.query(User).filter(User.username == "root").first()
        assert u is not None
        assert u.role == "admin"
        assert verify_password("rootroot", u.password_hash)

    # Second call should be a no-op (user already exists)
    ensure_bootstrap_admin()
    with session_scope() as s:
        assert s.query(User).count() == 1
