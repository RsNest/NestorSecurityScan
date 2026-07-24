"""User management UI (admin only)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database import session_scope
from app.models import User
from app.services.auth import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    CurrentUser,
    _load_user,
    hash_password,
    read_session,
)
from app.services.auth import SESSION_COOKIE

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
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Требуется роль admin"
        )
    return u


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request) -> HTMLResponse:
    current = _require_admin(request)
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
) -> RedirectResponse:
    current = _require_admin(request)
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
def users_delete(request: Request, user_id: int) -> RedirectResponse:
    current = _require_admin(request)
    if user_id == current.id:
        return RedirectResponse("/users", status_code=303)
    with session_scope() as session:
        u = session.get(User, user_id)
        if u:
            session.delete(u)
    return RedirectResponse("/users", status_code=303)
