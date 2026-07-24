"""Auth API: login, logout, me, user management (admin only)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.config import get_settings
from app.database import session_scope
from app.models import User
from app.services.auth import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    CurrentUser,
    SESSION_COOKIE,
    authenticate,
    hash_password,
    issue_session,
    require_role,
    require_user,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool
    created_at: str
    last_login_at: str | None = None


class MeResponse(BaseModel):
    id: int
    username: str
    role: str


def _to_out(u: User) -> UserOut:
    return UserOut(
        id=u.id,
        username=u.username,
        role=u.role,
        is_active=bool(u.is_active),
        created_at=u.created_at.isoformat() if u.created_at else "",
        last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
    )


@router.post("/login")
def login(body: LoginRequest, response: Response) -> MeResponse:
    user = authenticate(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
        )
    settings = get_settings()
    token = issue_session(user.id, settings)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=False,  # set True behind HTTPS reverse-proxy
        path="/",
    )
    return MeResponse(id=user.id, username=user.username, role=user.role)


@router.post("/logout")
def logout(response: Response) -> dict:
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: CurrentUser | None = Depends(require_user)) -> MeResponse:
    return MeResponse(id=user.id, username=user.username, role=user.role)


@router.get("/users", response_model=list[UserOut])
def list_users(_: CurrentUser = Depends(require_role(ROLE_ADMIN))) -> list[UserOut]:
    with session_scope() as session:
        users = session.query(User).order_by(User.id.asc()).all()
        for u in users:
            session.expunge(u)
    return [_to_out(u) for u in users]


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default=ROLE_VIEWER)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate, _: CurrentUser = Depends(require_role(ROLE_ADMIN))
) -> UserOut:
    if body.role not in {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}:
        raise HTTPException(status_code=400, detail="Неизвестная роль")
    with session_scope() as session:
        if session.query(User).filter(User.username == body.username).first():
            raise HTTPException(status_code=409, detail="Пользователь уже существует")
        user = User(
            username=body.username,
            password_hash=hash_password(body.password),
            role=body.role,
            is_active=1,
        )
        session.add(user)
        session.flush()
        session.refresh(user)
        session.expunge(user)
    return _to_out(user)


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=8, max_length=256)
    role: str | None = None
    is_active: bool | None = None


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int, body: UserUpdate, _: CurrentUser = Depends(require_role(ROLE_ADMIN))
) -> UserOut:
    with session_scope() as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        if body.password:
            user.password_hash = hash_password(body.password)
        if body.role is not None:
            if body.role not in {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}:
                raise HTTPException(status_code=400, detail="Неизвестная роль")
            user.role = body.role
        if body.is_active is not None:
            user.is_active = 1 if body.is_active else 0
        session.flush()
        session.refresh(user)
        session.expunge(user)
    return _to_out(user)


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int, current: CurrentUser = Depends(require_role(ROLE_ADMIN))
) -> None:
    if user_id == current.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить самого себя")
    with session_scope() as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        session.delete(user)
