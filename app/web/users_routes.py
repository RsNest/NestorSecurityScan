"""User management UI (admin only)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database import session_scope
from app.models import User
from app.services.auth import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    SESSION_COOKIE,
    CurrentUser,
    _load_user,
    hash_password,
    read_session,
)

router = APIRouter(tags=["web"])
_templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_dir))
templates.env.globals["app_name"] = get_settings().app_name


def _user_from_request(request: Request) -> CurrentUser | None:
    token = request.cookies.get(SESSION_COOKIE)
    uid = read_session(token)
    if not uid:
        return None
    u = _load_user(uid)
    if not u:
        return None
    return CurrentUser(u)


def _require_admin(request: Request) -> CurrentUser:
    u = _user_from_request(request)
    if not u:
        raise RedirectResponse("/login", status_code=303)
    if not u.has_role(ROLE_ADMIN):
        body = templates.get_template("error.html").render(
            {
                "request": request,
                "current_user": u,
                "page": "users",
                "status_code": 403,
                "title": "Недостаточно прав",
                "message": "Управление пользователями доступно только администраторам.",
                "back_url": "/",
                "back_label": "На дашборд",
                "app_name": get_settings().app_name,
            }
        )
        return HTMLResponse(content=body, status_code=403)
    return u


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request) -> HTMLResponse:
    current_or_response = _require_admin(request)
    if isinstance(current_or_response, HTMLResponse):
        return current_or_response
    current = current_or_response
    with session_scope() as session:
        users = session.query(User).order_by(User.id.asc()).all()
        for u in users:
            session.expunge(u)
    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "request": request,
            "current_user": current,
            "users": users,
            "error": None,
            "ok": None,
            "page": "users",
        },
    )


@router.post("/users/new")
def users_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(ROLE_VIEWER),
):
    current_or_response = _require_admin(request)
    if isinstance(current_or_response, HTMLResponse):
        return current_or_response
    current = current_or_response
    if role not in {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}:
        return templates.TemplateResponse(
            request,
            "users.html",
            {
                "request": request,
                "current_user": current,
                "users": [],
                "error": "Неизвестная роль",
                "ok": None,
                "page": "users",
            },
            status_code=400,
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            request,
            "users.html",
            {
                "request": request,
                "current_user": current,
                "users": [],
                "error": "Пароль должен быть ≥ 8 символов",
                "ok": None,
                "page": "users",
            },
            status_code=400,
        )
    with session_scope() as session:
        if session.query(User).filter(User.username == username).first():
            return templates.TemplateResponse(
                request,
                "users.html",
                {
                    "request": request,
                    "current_user": current,
                    "users": [],
                    "error": "Пользователь уже существует",
                    "ok": None,
                    "page": "users",
                },
                status_code=409,
            )
        session.add(
            User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                is_active=1,
            )
        )
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/delete")
def users_delete(request: Request, user_id: int):
    current_or_response = _require_admin(request)
    if isinstance(current_or_response, HTMLResponse):
        return current_or_response
    current = current_or_response
    if user_id == current.id:
        return RedirectResponse("/users", status_code=303)
    with session_scope() as session:
        u = session.get(User, user_id)
        if u:
            session.delete(u)
    return RedirectResponse("/users", status_code=303)
