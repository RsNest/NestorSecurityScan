"""Scan API endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse

from app.api.deps import require_api_key
from app.database import session_scope
from app.errors import ImageReferenceError, ScannerError
from app.models import Scan
from app.schemas import ScanCreate, ScanSummary
from app.services.report_generator import delete_report_dir, safe_report_dir
from app.workers.queue import cancel_job, enqueue_scan

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _to_summary(scan: Scan) -> ScanSummary:
    duration = None
    if scan.started_at and scan.finished_at:
        duration = (scan.finished_at - scan.started_at).total_seconds()
    return ScanSummary(
        id=scan.id,
        source=scan.source,
        requested_image=scan.requested_image,
        canonical_image=scan.canonical_image,
        registry=scan.registry,
        repository=scan.repository,
        tag=scan.tag,
        digest=scan.digest,
        status=scan.status,
        stage=scan.stage,
        progress=scan.progress,
        message=scan.message,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        total_vulns=scan.total_vulns,
        unique_cve_count=scan.unique_cve_count,
        fixable_count=scan.fixable_count,
        kev_count=scan.kev_count,
        policy_name=scan.policy_name,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error_message=scan.error_message,
        syft_version=scan.syft_version,
        grype_version=scan.grype_version,
        grype_db_built_at=scan.grype_db_built_at,
        duration_seconds=duration,
    )


@router.post("", response_model=ScanSummary, status_code=status.HTTP_201_CREATED)
def create_scan(body: ScanCreate, _: None = Depends(require_api_key)) -> ScanSummary:
    try:
        scan, created = enqueue_scan(
            image=body.image,
            source=body.source,
            registry_username=body.registry_username,
            registry_password=body.registry_password,
            platform=body.platform,
            webhook_event_id=body.webhook_event_id,
        )
    except ImageReferenceError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    except ScannerError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return _to_summary(scan)


@router.get("", response_model=list[ScanSummary])
def list_scans(
    status_filter: str | None = Query(default=None, alias="status"),
    source: str | None = None,
    image: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[ScanSummary]:
    with session_scope() as session:
        q = session.query(Scan).order_by(Scan.created_at.desc())
        if status_filter:
            q = q.filter(Scan.status == status_filter)
        if source:
            q = q.filter(Scan.source == source)
        if image:
            q = q.filter(Scan.requested_image.contains(image))
        scans = q.limit(limit).all()
        for s in scans:
            session.expunge(s)
    return [_to_summary(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanSummary)
def get_scan(scan_id: str) -> ScanSummary:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Сканирование не найдено")
        session.expunge(scan)
    return _to_summary(scan)


@router.post("/{scan_id}/rescan", response_model=ScanSummary, status_code=201)
def rescan(scan_id: str, _: None = Depends(require_api_key)) -> ScanSummary:
    with session_scope() as session:
        parent = session.get(Scan, scan_id)
        if not parent:
            raise HTTPException(status_code=404, detail="Сканирование не найдено")
        image = parent.requested_image
        session.expunge(parent)
    scan, _ = enqueue_scan(
        image=image,
        source="rescan",
        parent_scan_id=scan_id,
        rescan=True,
    )
    return _to_summary(scan)


@router.post("/{scan_id}/cancel", response_model=ScanSummary)
def cancel(scan_id: str, _: None = Depends(require_api_key)) -> ScanSummary:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Сканирование не найдено")
    cancel_job(scan_id)
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        assert scan
        session.expunge(scan)
    return _to_summary(scan)


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, _: None = Depends(require_api_key)) -> None:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Сканирование не найдено")
        session.delete(scan)
    try:
        delete_report_dir(scan_id)
    except Exception:  # noqa: BLE001
        pass


def _file_response(scan_id: str, filename: str, media: str) -> FileResponse:
    path = safe_report_dir(scan_id) / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Файл {filename} не найден")
    return FileResponse(path, media_type=media, filename=filename)


@router.get("/{scan_id}/report.json")
def report_json(scan_id: str) -> FileResponse:
    return _file_response(scan_id, "normalized-report.json", "application/json")


@router.get("/{scan_id}/report.html")
def report_html(scan_id: str) -> FileResponse:
    return _file_response(scan_id, "report.html", "text/html")


@router.get("/{scan_id}/sbom/syft")
def sbom_syft(scan_id: str) -> FileResponse:
    return _file_response(scan_id, "sbom.syft.json", "application/json")


@router.get("/{scan_id}/sbom/cyclonedx")
def sbom_cyclonedx(scan_id: str) -> FileResponse:
    return _file_response(scan_id, "sbom.cyclonedx.json", "application/json")


@router.get("/{scan_id}/grype")
def grype_json(scan_id: str) -> FileResponse:
    return _file_response(scan_id, "grype.json", "application/json")
