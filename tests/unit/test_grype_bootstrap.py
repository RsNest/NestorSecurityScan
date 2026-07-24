"""Grype DB bootstrap and readiness helpers."""

from app.schemas import GrypeDbStatus
from app.services.grype_db import NETWORK_HINT, _humanize_update_error, readiness_code


def test_humanize_network_error():
    msg = _humanize_update_error("dial tcp: lookup grype.anchore.io: no such host")
    assert "grype.anchore.io" in msg
    assert msg.startswith(NETWORK_HINT[:20]) or "База уязвимостей" in msg


def test_readiness_code_not_ready(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "grype"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    import app.database as database
    from app.config import get_settings
    from app.database import Base, create_db_engine

    get_settings.cache_clear()
    database.engine = create_db_engine(f"sqlite:///{tmp_path}/t.db")
    database.SessionLocal.configure(bind=database.engine)
    Base.metadata.create_all(bind=database.engine)

    assert readiness_code() in {"not_ready", "error", "updating"}
    get_settings.cache_clear()


def test_grype_status_fields():
    status = GrypeDbStatus(ready=False, bootstrapping=True, last_update_status="updating")
    assert status.bootstrapping is True
    assert status.ready is False
