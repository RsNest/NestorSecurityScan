"""Server-side web UI routes (Jinja2 + HTMX)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database import session_scope
from app.errors import HarborError, ImageReferenceError
from app.models import ACTIVE_SCAN_STATUSES, Scan
from app.services.grype_db import get_grype_db_status
from app.services.harbor_client import HarborClient
from app.services.report_generator import safe_report_dir
from app.workers.queue import cancel_job, enqueue_scan

router = APIRouter(tags=["web"])
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)
templates.env.globals["app_name"] = get_settings().app_name


def _dashboard_stats() -> dict:
    with session_scope() as session:
        total = session.query(Scan).count()
        compliant = session.query(Scan).filter(Scan.status == "COMPLIANT").count()
        compliant_exc = (
            session.query(Scan)
            .filter(Scan.status == "COMPLIANT_WITH_EXCEPTIONS")
            .count()
        )
        non_compliant = (
            session.query(Scan).filter(Scan.status == "NON_COMPLIANT").count()
        )
        running = (
            session.query(Scan).filter(Scan.status.in_(ACTIVE_SCAN_STATUSES)).count()
        )
        recent = session.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
        vulnerable = (
            session.query(Scan)
            .filter(
                Scan.status.in_(
                    ["NON_COMPLIANT", "COMPLIANT_WITH_EXCEPTIONS", "COMPLIANT"]
                )
            )
            .order_by((Scan.critical_count + Scan.high_count).desc())
            .limit(5)
            .all()
        )
        for s in {x.id: x for x in (recent + vulnerable)}.values():
            session.expunge(s)
    return {
        "total": total,
        "compliant": compliant + compliant_exc,
        "non_compliant": non_compliant,
        "running": running,
        "recent": recent,
        "vulnerable": vulnerable,
    }


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    stats = _dashboard_stats()
    grype = get_grype_db_status()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"stats": stats, "grype": grype, "page": "dashboard"},
    )


@router.get("/scans", response_class=HTMLResponse)
def scans_page(
    request: Request,
    status: str | None = None,
    source: str | None = None,
    image: str | None = None,
) -> HTMLResponse:
    with session_scope() as session:
        q = session.query(Scan).order_by(Scan.created_at.desc())
        if status:
            q = q.filter(Scan.status == status)
        if source:
            q = q.filter(Scan.source == source)
        if image:
            q = q.filter(Scan.requested_image.contains(image))
        scans = q.limit(100).all()
        for s in scans:
            session.expunge(s)
    return templates.TemplateResponse(
        request,
        "scans.html",
        {
            "scans": scans,
            "filters": {
                "status": status or "",
                "source": source or "",
                "image": image or "",
            },
            "page": "scans",
        },
    )


@router.get("/scans/new", response_class=HTMLResponse)
def new_scan_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "scan_new.html",
        {"page": "new", "error": None, "image": "", "grype": get_grype_db_status()},
    )


@router.post("/scans/new", response_class=HTMLResponse)
def new_scan_submit(
    request: Request,
    image: str = Form(...),
    registry_username: str = Form(""),
    registry_password: str = Form(""),
    platform: str = Form(""),
) -> HTMLResponse:
    try:
        scan, _ = enqueue_scan(
            image=image.strip(),
            source="manual",
            registry_username=registry_username or None,
            registry_password=registry_password or None,
            platform=platform or None,
        )
        return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)
    except Exception as exc:  # noqa: BLE001
        msg = getattr(exc, "message", str(exc))
        return templates.TemplateResponse(
            request,
            "scan_new.html",
            {
                "page": "new",
                "error": msg,
                "image": image,
                "grype": get_grype_db_status(),
            },
            status_code=400,
        )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: str) -> HTMLResponse:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return templates.TemplateResponse(
                request,
                "scan_detail.html",
                {"page": "scans", "scan": None, "error": "Не найдено", "vulns": [], "log_tail": ""},
                status_code=404,
            )
        session.expunge(scan)

    vulns = []
    log_tail = ""
    try:
        report_path = safe_report_dir(scan_id) / "normalized-report.json"
        if report_path.exists():
            data = json.loads(report_path.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities") or []
        log_path = safe_report_dir(scan_id) / "scan.log"
        if log_path.exists():
            log_tail = log_path.read_text(encoding="utf-8")[-8000:]
    except Exception:  # noqa: BLE001
        pass

    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {
            "page": "scans",
            "scan": scan,
            "vulns": vulns[:200],
            "log_tail": log_tail,
            "error": None,
        },
    )


@router.get("/scans/{scan_id}/fragment", response_class=HTMLResponse)
def scan_fragment(request: Request, scan_id: str) -> HTMLResponse:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return HTMLResponse("Не найдено", status_code=404)
        session.expunge(scan)
    return templates.TemplateResponse(
        request,
        "partials/scan_progress.html",
        {"scan": scan},
    )


@router.post("/scans/{scan_id}/rescan")
def ui_rescan(scan_id: str) -> RedirectResponse:
    with session_scope() as session:
        parent = session.get(Scan, scan_id)
        if not parent:
            return RedirectResponse("/scans", status_code=303)
        image = parent.requested_image
    scan, _ = enqueue_scan(
        image=image, source="rescan", parent_scan_id=scan_id, rescan=True
    )
    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


@router.post("/scans/{scan_id}/cancel")
def ui_cancel(scan_id: str) -> RedirectResponse:
    cancel_job(scan_id)
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@router.post("/scans/{scan_id}/delete")
def ui_delete(scan_id: str) -> RedirectResponse:
    from app.services.report_generator import delete_report_dir

    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan:
            session.delete(scan)
    try:
        delete_report_dir(scan_id)
    except Exception:  # noqa: BLE001
        pass
    return RedirectResponse(url="/scans", status_code=303)


@router.get("/harbor", response_class=HTMLResponse)
def harbor_page(
    request: Request,
    project: str | None = None,
    repository: str | None = None,
) -> HTMLResponse:
    settings = get_settings()
    status = {
        "enabled": settings.harbor_enabled,
        "url": settings.harbor_url,
        "message": None,
        "reachable": None,
    }
    projects: list = []
    repositories: list = []
    artifacts: list = []
    error = None
    if settings.harbor_enabled and settings.harbor_url:
        try:
            client = HarborClient(settings)
            client.ping()
            status["reachable"] = True
            status["message"] = "Соединение успешно"
            projects = client.list_projects()
            filters = set(settings.harbor_project_filters)
            if filters:
                projects = [p for p in projects if p.get("name") in filters]
            if project:
                repositories = client.list_repositories(project)
            if project and repository:
                artifacts = client.list_artifacts(project, repository)
                host = (
                    settings.harbor_url.replace("https://", "")
                    .replace("http://", "")
                    .split("/")[0]
                )
                for art in artifacts:
                    digest = art.get("digest")
                    tags = art.get("tags") or []
                    tag = tags[0].get("name") if tags else None
                    full = f"{project}/{repository}"
                    art["_image_ref"] = (
                        f"{host}/{full}:{tag}" if tag else f"{host}/{full}@{digest}"
                    )
        except HarborError as exc:
            status["reachable"] = False
            status["message"] = exc.message
            error = exc.message
    else:
        status["message"] = "Настройте Harbor в .env (HARBOR_ENABLED=true)"

    return templates.TemplateResponse(
        request,
        "harbor.html",
        {
            "page": "harbor",
            "status": status,
            "projects": projects,
            "repositories": repositories,
            "artifacts": artifacts,
            "selected_project": project,
            "selected_repository": repository,
            "error": error,
        },
    )


@router.post("/harbor/scan")
async def harbor_scan_ui(request: Request) -> RedirectResponse:
    form = await request.form()
    images = form.getlist("images")
    for image in images:
        enqueue_scan(image=str(image), source="harbor")
    return RedirectResponse(url="/scans", status_code=303)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> HTMLResponse:
    settings = get_settings()
    grype = get_grype_db_status()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "page": "settings",
            "settings": settings,
            "grype": grype,
            "api_key_set": bool(settings.api_key),
        },
    )
