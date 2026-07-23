"""Settings / Grype DB status API."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import require_api_key
from app.config import get_settings
from app.schemas import GrypeDbStatus
from app.services.grype_db import get_grype_db_status, update_grype_db

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("/grype-db", response_model=GrypeDbStatus)
def grype_db_status() -> GrypeDbStatus:
    return get_grype_db_status()


@router.post("/grype-db/update", response_model=GrypeDbStatus)
def grype_db_update(_: None = Depends(require_api_key)) -> GrypeDbStatus:
    return update_grype_db()


@router.get("/info")
def settings_info() -> dict:
    s = get_settings()
    return {
        "app_name": s.app_name,
        "app_env": s.app_env,
        "harbor_enabled": s.harbor_enabled,
        "harbor_url": s.harbor_url or None,
        "discovery_enabled": s.discovery_enabled,
        "discovery_interval_minutes": s.discovery_interval_minutes,
        "policy_file": str(s.policy_file),
        "api_key_configured": bool(s.api_key),
        "grype_db_update_interval_hours": s.grype_db_update_interval_hours,
        "report_retention_days": s.report_retention_days,
        "max_concurrent_scans": s.max_concurrent_scans,
    }
