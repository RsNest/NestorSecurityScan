"""Server-side web UI routes (Jinja2 + HTMX)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database import session_scope
from app.errors import HarborError, ImageReferenceError
from app.models import Scan
from app.services.auth import (
    SESSION_COOKIE,
    CurrentUser,
    authenticate,
    issue_session,
    read_session,
)
from app.services.github_registry import GitHubRegistryClient, GitHubRegistryError
from app.services.grype_db import get_grype_db_status
from app.services.harbor_client import HarborClient
from app.services.posture import security_posture
from app.services.report_generator import delete_report_dir, safe_report_dir
from app.workers.queue import cancel_job, enqueue_scan

router = APIRouter(tags=["web"])
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)
templates.env.globals["app_name"] = get_settings().app_name


def _ctx(request: Request, user: CurrentUser | None, **extra) -> dict:
    return {"request": request, "current_user": user, **extra}


def _require_session_user(request: Request) -> CurrentUser | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    from app.services.auth import _load_user  # local import to avoid cycles

    uid = read_session(token)
    if not uid:
        return None
    return _load_user(uid)


# ---------- public ----------

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    user = _require_session_user(request)
    if user:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    user = authenticate(username, password)
    if not user:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Неверное имя пользователя или пароль"},
            status_code=401,
        )
    settings = get_settings()
    token = issue_session(user.id, settings)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return resp


@router.post("/logout")
def logout_submit() -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# ---------- protected (redirect to /login) ----------

def _gate(request: Request) -> CurrentUser | None:
    user = _require_session_user(request)
    if not user:
        # For HTML routes we redirect; API has its own 401 via deps
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return user


# ---------- dashboard ----------

def _dashboard_recent() -> list[Scan]:
    with session_scope() as session:
        items = session.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
        for s in items:
            session.expunge(s)
    return items


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _user: CurrentUser = Depends(_gate)) -> HTMLResponse:
    posture = security_posture()
    grype = get_grype_db_status()
    recent = _dashboard_recent()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _ctx(
            request,
            _require_session_user(request),
            posture=posture,
            grype=grype,
            recent=recent,
            page="dashboard",
        ),
    )


# ---------- scans ----------

@router.get("/scans", response_class=HTMLResponse)
def scans_page(
    request: Request,
    _user: CurrentUser = Depends(_gate),
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
        _ctx(
            request,
            _require_session_user(request),
            scans=scans,
            filters={"status": status or "", "source": source or "", "image": image or ""},
            page="scans",
        ),
    )


@router.get("/scans/new", response_class=HTMLResponse)
def new_scan_page(
    request: Request, _user: CurrentUser = Depends(_gate)
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "scan_new.html",
        _ctx(
            request,
            _require_session_user(request),
            page="new",
            error=None,
            image="",
            grype=get_grype_db_status(),
        ),
    )


@router.post("/scans/new", response_class=HTMLResponse)
def new_scan_submit(
    request: Request,
    _user: CurrentUser = Depends(_gate),
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
    except (ImageReferenceError, HarborError) as exc:
        msg = getattr(exc, "message", str(exc))
        return templates.TemplateResponse(
            request,
            "scan_new.html",
            _ctx(
                request,
                _require_session_user(request),
                page="new",
                error=msg,
                image=image,
                grype=get_grype_db_status(),
            ),
            status_code=400,
        )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(
    request: Request, scan_id: str, _user: CurrentUser = Depends(_gate)
) -> HTMLResponse:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return templates.TemplateResponse(
                request,
                "scan_detail.html",
                _ctx(
                    request,
                    _require_session_user(request),
                    page="scans",
                    scan=None,
                    error="Не найдено",
                    vulns=[],
                    log_tail="",
                ),
                status_code=404,
            )
        session.expunge(scan)

    vulns: list = []
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
        _ctx(
            request,
            _require_session_user(request),
            page="scans",
            scan=scan,
            vulns=vulns[:200],
            log_tail=log_tail,
            error=None,
        ),
    )


@router.get("/scans/{scan_id}/fragment", response_class=HTMLResponse)
def scan_fragment(
    request: Request, scan_id: str, _user: CurrentUser = Depends(_gate)
) -> HTMLResponse:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return HTMLResponse("Не найдено", status_code=404)
        session.expunge(scan)
    return templates.TemplateResponse(
        request, "partials/scan_progress.html", {"scan": scan}
    )


@router.post("/scans/{scan_id}/rescan")
def ui_rescan(scan_id: str, _user: CurrentUser = Depends(_gate)) -> RedirectResponse:
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
def ui_cancel(scan_id: str, _user: CurrentUser = Depends(_gate)) -> RedirectResponse:
    cancel_job(scan_id)
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@router.post("/scans/{scan_id}/delete")
def ui_delete(scan_id: str, _user: CurrentUser = Depends(_gate)) -> RedirectResponse:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan:
            session.delete(scan)
    try:
        delete_report_dir(scan_id)
    except Exception:  # noqa: BLE001
        pass
    return RedirectResponse(url="/scans", status_code=303)


# ---------- Harbor ----------

@router.get("/harbor", response_class=HTMLResponse)
def harbor_page(
    request: Request,
    _user: CurrentUser = Depends(_gate),
    project: str | None = None,
    repository: str | None = None,
) -> HTMLResponse:
    settings = get_settings()
    status_obj = {
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
            status_obj["reachable"] = True
            status_obj["message"] = "Соединение успешно"
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
            status_obj["reachable"] = False
            status_obj["message"] = exc.message
            error = exc.message
    else:
        status_obj["message"] = "Настройте Harbor в .env (HARBOR_ENABLED=true)"

    return templates.TemplateResponse(
        request,
        "harbor.html",
        _ctx(
            request,
            _require_session_user(request),
            page="harbor",
            status=status_obj,
            projects=projects,
            repositories=repositories,
            artifacts=artifacts,
            selected_project=project,
            selected_repository=repository,
            error=error,
        ),
    )


@router.post("/harbor/scan")
async def harbor_scan_ui(
    request: Request, _user: CurrentUser = Depends(_gate)
) -> RedirectResponse:
    form = await request.form()
    images = form.getlist("images")
    for image in images:
        enqueue_scan(image=str(image), source="harbor")
    return RedirectResponse(url="/scans", status_code=303)


# ---------- GitHub / GHCR ----------

@router.get("/github", response_class=HTMLResponse)
def github_page(
    request: Request,
    _user: CurrentUser = Depends(_gate),
    owner: str | None = None,
    package: str | None = None,
) -> HTMLResponse:
    settings = get_settings()
    ctx_status = {
        "enabled": bool(settings.github_token),
        "reachable": None,
        "message": None,
    }
    packages: list = []
    versions: list = []
    image_refs: list = []
    error = None

    if not settings.github_token:
        ctx_status["message"] = "Укажите GITHUB_TOKEN в .env (PAT с правами read:packages)"
    else:
        try:
            client = GitHubRegistryClient(settings)
            client.ping()
            ctx_status["reachable"] = True
            ctx_status["message"] = "GitHub-аутентификация успешна"
            if owner:
                packages = client.list_container_repositories(owner=owner)
            if owner and package:
                versions = client.list_tags(owner, package)
                image_refs = client.list_artifacts(owner, package)
        except GitHubRegistryError as exc:
            ctx_status["reachable"] = False
            ctx_status["message"] = exc.message
            error = exc.message

    return templates.TemplateResponse(
        request,
        "github.html",
        _ctx(
            request,
            _require_session_user(request),
            page="github",
            status=ctx_status,
            packages=packages,
            versions=versions,
            image_refs=image_refs,
            selected_owner=owner,
            selected_package=package,
            error=error,
        ),
    )


@router.post("/github/scan")
async def github_scan_ui(
    request: Request, _user: CurrentUser = Depends(_gate)
) -> RedirectResponse:
    form = await request.form()
    images = form.getlist("images")
    for image in images:
        enqueue_scan(image=str(image), source="github")
    return RedirectResponse(url="/scans", status_code=303)


# ---------- settings ----------

@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request, _user: CurrentUser = Depends(_gate)
) -> HTMLResponse:
    settings = get_settings()
    grype = get_grype_db_status()
    return templates.TemplateResponse(
        request,
        "settings.html",
        _ctx(
            request,
            _require_session_user(request),
            page="settings",
            settings=settings,
            grype=grype,
            api_key_set=bool(settings.api_key),
        ),
    )
