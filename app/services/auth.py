"""Authentication, password hashing, cookie sessions and RBAC helpers."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import bcrypt
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import Settings, get_settings
from app.database import session_scope
from app.models import User

logger = logging.getLogger(__name__)

SESSION_COOKIE = "nss_session"

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"

ROLE_RANK = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _serializer(settings: Settings | None = None) -> URLSafeTimedSerializer:
    s = settings or get_settings()
    return URLSafeTimedSerializer(s.session_secret, salt="nss-session")


def issue_session(user_id: int, settings: Settings | None = None) -> str:
    s = _serializer(settings)
    return s.dumps({"uid": user_id})


def read_session(token: str | None, settings: Settings | None = None) -> int | None:
    if not token:
        return None
    s = _serializer(settings)
    try:
        data = s.loads(token, max_age=get_settings().session_max_age_seconds)
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    uid = data.get("uid") if isinstance(data, dict) else None
    return int(uid) if isinstance(uid, int) else None


def authenticate(username: str, password: str) -> User | None:
    if not username or not password:
        return None
    with session_scope() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.password_hash):
            return None
        user.last_login_at = datetime.now(UTC)
        session.expunge(user)
    return user


def ensure_bootstrap_admin() -> None:
    """Create initial admin from ADMIN_USER/ADMIN_PASSWORD if no users exist."""
    settings = get_settings()
    if not settings.admin_user or not settings.admin_password:
        return
    with session_scope() as session:
        has_any = session.query(User).count() > 0
        if has_any:
            return
        session.add(
            User(
                username=settings.admin_user,
                password_hash=hash_password(settings.admin_password),
                role=ROLE_ADMIN,
                is_active=1,
            )
        )
        logger.warning(
            "Bootstrap admin '%s' created from ADMIN_USER env", settings.admin_user
        )


def _load_user(user_id: int) -> User | None:
    with session_scope() as session:
        user = session.get(User, user_id)
        if not user or not user.is_active:
            return None
        session.expunge(user)
    return user


class CurrentUser:
    __slots__ = ("id", "username", "role")

    def __init__(self, user: User):
        self.id = user.id
        self.username = user.username
        self.role = user.role

    def has_role(self, minimum: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK.get(minimum, 99)

    def __repr__(self) -> str:  # pragma: no cover
        return f"CurrentUser(id={self.id}, username={self.username!r}, role={self.role!r})"


def get_current_user(
    request: Request,
    nss_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    x_api_key: str | None = None,
) -> CurrentUser | None:
    settings = get_settings()
    # Legacy API key path: if set and matches X-API-Key, allow as "operator".
    # We don't know role from the key, so we don't have a User; return None
    # and let require_legacy_api_key be used instead for that flow.
    if not nss_session:
        return None
    user_id = read_session(nss_session)
    if not user_id:
        return None
    user = _load_user(user_id)
    if not user:
        return None
    return CurrentUser(user)


def authorize(
    request: Request,
    minimum: str = "operator",
    nss_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    x_api_key: str | None = None,
) -> CurrentUser:
    """Authorise either via session cookie (any role >= minimum) or via
    legacy X-API-Key (treated as operator).

    - 401 when there is no valid session at all
    - 403 when there IS a valid session but the role is too low
    """
    settings = get_settings()
    if settings.api_key and x_api_key and x_api_key == settings.api_key:
        return _legacy_principal()
    if nss_session:
        user_id = read_session(nss_session)
        if user_id:
            user = _load_user(user_id)
            if user:
                cu = CurrentUser(user)
                if cu.has_role(minimum):
                    return cu
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Недостаточно прав (требуется роль {minimum})",
                )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Требуется аутентификация (сессия или X-API-Key)",
    )


def _legacy_principal() -> CurrentUser:
    """In-memory principal for legacy X-API-Key (no DB row)."""
    obj = CurrentUser.__new__(CurrentUser)
    obj.id = 0
    obj.username = "legacy-api-key"
    obj.role = ROLE_OPERATOR
    return obj


def require_user(user: CurrentUser | None = Depends(get_current_user)) -> CurrentUser:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется вход в систему",
        )
    return user


def require_role(minimum: str):
    """Dependency: session cookie (role >= minimum) OR legacy X-API-Key (operator)."""
    def _dep(
        request: Request,
        nss_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> CurrentUser:
        return authorize(request, minimum=minimum, nss_session=nss_session, x_api_key=x_api_key)

    return _dep


def require_legacy_api_key(x_api_key: str | None = None) -> bool:
    """Allow X-API-Key for CI/integrations. Returns True if authorised."""
    settings = get_settings()
    if not settings.api_key:
        return True
    return bool(x_api_key) and x_api_key == settings.api_key
