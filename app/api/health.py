"""Health and version endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app import __version__
from app.config import get_settings
from app.database import engine
from app.schemas import HealthResponse, VersionResponse
from app.services.grype_db import readiness_code
from app.services.grype_runner import get_grype_version
from app.services.syft_runner import get_syft_version
from app.workers.queue import get_redis

router = APIRouter(tags=["health"])


@router.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    db_status = "ok"
    redis_status = "ok"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        db_status = "error"
    try:
        get_redis().ping()
    except Exception:  # noqa: BLE001
        redis_status = "error"

    grype_status = readiness_code()
    if db_status != "ok" or redis_status != "ok":
        overall = "degraded"
    elif grype_status in {"not_ready", "updating"}:
        overall = "db_not_ready"
    elif grype_status == "error":
        overall = "degraded"
    else:
        overall = "ok"

    return HealthResponse(
        status=overall,
        service=settings.service_name,
        redis=redis_status,
        database=db_status,
        grype_db=grype_status,
        version=__version__,
    )


@router.get("/api/v1/version", response_model=VersionResponse)
def version() -> VersionResponse:
    return VersionResponse(
        app_version=__version__,
        syft_version=get_syft_version(),
        grype_version=get_grype_version(),
    )
