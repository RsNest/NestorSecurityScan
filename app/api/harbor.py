"""Harbor API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import require_api_key
from app.config import get_settings
from app.errors import HarborError
from app.schemas import HarborScanRequest, HarborStatus, ScanSummary
from app.services.auth import CurrentUser, require_role
from app.services.harbor_client import HarborClient
from app.workers.queue import enqueue_scan
from app.api.scans import _to_summary

router = APIRouter(prefix="/api/v1/harbor", tags=["harbor"])


def _client() -> HarborClient:
    settings = get_settings()
    if not settings.harbor_enabled:
        raise HTTPException(status_code=400, detail="Harbor отключён (HARBOR_ENABLED=false)")
    try:
        return HarborClient(settings)
    except HarborError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc


@router.get("/status", response_model=HarborStatus)
def harbor_status() -> HarborStatus:
    settings = get_settings()
    configured = bool(settings.harbor_url and settings.harbor_username)
    if not settings.harbor_enabled:
        return HarborStatus(
            enabled=False,
            configured=configured,
            reachable=None,
            url=settings.harbor_url or None,
            message="Harbor отключён",
        )
    try:
        client = HarborClient(settings)
        client.ping()
        return HarborStatus(
            enabled=True,
            configured=configured,
            reachable=True,
            url=settings.harbor_url,
            message="Соединение успешно",
        )
    except HarborError as exc:
        return HarborStatus(
            enabled=True,
            configured=configured,
            reachable=False,
            url=settings.harbor_url or None,
            message=exc.message,
        )


@router.get("/projects")
def list_projects() -> list[dict]:
    try:
        projects = _client().list_projects()
    except HarborError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc
    filters = set(get_settings().harbor_project_filters)
    if filters:
        projects = [p for p in projects if p.get("name") in filters]
    return projects


@router.get("/projects/{project}/repositories")
def list_repositories(project: str) -> list[dict]:
    try:
        return _client().list_repositories(project)
    except HarborError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc


@router.get("/projects/{project}/repositories/{repository:path}/artifacts")
def list_artifacts(project: str, repository: str) -> list[dict]:
    try:
        return _client().list_artifacts(project, repository)
    except HarborError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc


@router.post("/scan", response_model=list[ScanSummary])
def harbor_scan(
    body: HarborScanRequest,
    _: CurrentUser = Depends(require_role("operator")),
) -> list[ScanSummary]:
    results = []
    for image in body.images:
        scan, _ = enqueue_scan(image=image, source="harbor", platform=body.platform)
        results.append(_to_summary(scan))
    return results
