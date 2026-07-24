"""Tests for security_posture aggregator and rescan helper."""

from datetime import timedelta

from app.database import session_scope
from app.models import Scan, utcnow
from app.services.posture import security_posture


def _mk_scan(digest: str, status: str, days_ago: int, c: int = 0, h: int = 0, kev: int = 0):
    s = Scan(
        id=digest.replace(":", "-"),
        source="manual",
        requested_image=f"image-{digest}",
        canonical_image=f"image-{digest}",
        digest=digest,
        status=status,
        created_at=utcnow() - timedelta(days=days_ago),
        finished_at=utcnow() - timedelta(days=days_ago),
        critical_count=c,
        high_count=h,
        kev_count=kev,
    )
    with session_scope() as sess:
        sess.add(s)


def test_security_posture_aggregates(tmp_path, monkeypatch):
    db = tmp_path / "p.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv("SESSION_SECRET", "x" * 40)
    from app.config import get_settings
    get_settings.cache_clear()
    import app.database as db_mod
    from app.database import Base, create_db_engine
    db_mod.engine = create_db_engine(f"sqlite:///{db}")
    db_mod.SessionLocal.configure(bind=db_mod.engine)
    Base.metadata.create_all(bind=db_mod.engine)

    _mk_scan("sha256:01", "COMPLIANT", 0, c=0, h=0)
    _mk_scan("sha256:02", "NON_COMPLIANT", 1, c=3, h=5, kev=1)
    _mk_scan("sha256:03", "ERROR", 0)
    _mk_scan("sha256:04", "QUEUED", 0)

    p = security_posture()
    assert p["total"] == 4
    assert p["compliant"] == 1
    assert p["non_compliant"] == 1
    assert p["error"] == 1
    assert p["kev_total"] == 1
    assert p["critical_total"] == 3
    assert p["high_total"] == 5
    assert any(t["id"] == "sha256-02" for t in p["top_vulnerable"])
    assert len(p["trend"]) == 7
