"""Grype vulnerability database status, bootstrap and updates."""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.database import session_scope
from app.models import AppState
from app.schemas import GrypeDbStatus
from app.services.subprocess_runner import run_command

logger = logging.getLogger(__name__)

KEYS = (
    "grype_db_built_at",
    "grype_db_schema_version",
    "grype_db_last_check_at",
    "grype_db_last_update_at",
    "grype_db_last_update_status",
    "grype_db_last_error",
)

NETWORK_HINT = (
    "База уязвимостей Grype не инициализирована или недоступна. "
    "Требуется сеть до grype.anchore.io (или зеркала) для первой загрузки. "
    "Проверьте firewall/proxy и выполните make update-db."
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_state(values: dict[str, str | None]) -> None:
    """Short transaction write for app_state."""
    with session_scope() as session:
        for key, value in values.items():
            row = session.get(AppState, key)
            if row is None:
                session.add(AppState(key=key, value=value))
            else:
                row.value = value


def _get_state() -> dict[str, str | None]:
    """Short transaction read for app_state."""
    with session_scope() as session:
        rows = session.query(AppState).filter(AppState.key.in_(KEYS)).all()
        return {row.key: row.value for row in rows}


def parse_db_status_output(text: str) -> dict[str, str | None]:
    built_at = None
    schema = None
    for line in (text or "").splitlines():
        lower = line.lower()
        if "built" in lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                built_at = parts[1].strip()
        if "schema" in lower:
            match = re.search(r"(\d+)", line)
            if match:
                schema = match.group(1)
    return {"built_at": built_at, "schema_version": schema}


def _humanize_update_error(stderr: str, returncode: int | None = None) -> str:
    text = (stderr or "").lower()
    if any(
        token in text
        for token in (
            "connection refused",
            "network is unreachable",
            "temporary failure in name resolution",
            "no such host",
            "i/o timeout",
            "tls handshake timeout",
            "proxyconnect",
            "dial tcp",
            "eof",
            "unavailable",
        )
    ):
        return NETWORK_HINT + f" Детали: {(stderr or '')[:400]}"
    if "no database" in text or "database does not exist" in text:
        return NETWORK_HINT
    suffix = f" (код {returncode})" if returncode is not None else ""
    return f"Не удалось обновить базу Grype{suffix}: {(stderr or 'без деталей')[:500]}"


def cli_db_present() -> tuple[bool, dict[str, str | None]]:
    """Return whether grype reports a usable local DB."""
    settings = get_settings()
    result = run_command(
        [settings.grype_bin, "db", "status"],
        timeout_seconds=60,
        env={"GRYPE_DB_CACHE_DIR": str(settings.grype_db_cache_dir)},
    )
    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    lower = combined.lower()
    parsed = parse_db_status_output(combined)
    missing = (
        result.returncode != 0
        or "no database" in lower
        or "does not exist" in lower
        or "not found" in lower
        or not parsed.get("built_at")
    )
    # Also check cache dir has content
    cache = settings.grype_db_cache_dir
    has_files = cache.exists() and any(cache.iterdir())
    present = not missing and has_files
    return present, parsed


def get_grype_db_status() -> GrypeDbStatus:
    data = _get_state()
    status = data.get("grype_db_last_update_status")
    built = data.get("grype_db_built_at")
    ready = bool(built) and status != "updating"
    bootstrapping = status == "updating" or (not built and status not in {"error", "success"})
    if status == "updating":
        bootstrapping = True
        ready = False
    elif not built:
        bootstrapping = status != "error"
        ready = False
    return GrypeDbStatus(
        built_at=built,
        schema_version=data.get("grype_db_schema_version"),
        last_check_at=data.get("grype_db_last_check_at"),
        last_update_at=data.get("grype_db_last_update_at"),
        last_update_status=status,
        last_error=data.get("grype_db_last_error"),
        stale=status == "error",
        ready=ready,
        bootstrapping=bootstrapping and not ready,
    )


def is_grype_db_ready() -> bool:
    status = get_grype_db_status()
    if status.ready and status.built_at:
        return True
    present, _ = cli_db_present()
    return present


def refresh_status_from_cli() -> GrypeDbStatus:
    present, parsed = cli_db_present()
    now = _now_iso()
    current = _get_state()
    if present:
        _set_state(
            {
                "grype_db_built_at": parsed.get("built_at") or current.get("grype_db_built_at"),
                "grype_db_schema_version": parsed.get("schema_version"),
                "grype_db_last_check_at": now,
                "grype_db_last_update_status": current.get("grype_db_last_update_status")
                or "success",
            }
        )
    else:
        _set_state({"grype_db_last_check_at": now})
    return get_grype_db_status()


def _lock_path() -> Path:
    settings = get_settings()
    settings.grype_db_cache_dir.mkdir(parents=True, exist_ok=True)
    return settings.grype_db_cache_dir / ".bootstrap.lock"


def update_grype_db() -> GrypeDbStatus:
    """Run grype db update. Failures do NOT permanently block scanning once a DB exists."""
    settings = get_settings()
    settings.grype_db_cache_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Updating Grype DB")
    _set_state(
        {
            "grype_db_last_update_status": "updating",
            "grype_db_last_error": None,
            "grype_db_last_check_at": _now_iso(),
        }
    )
    try:
        result = run_command(
            [settings.grype_bin, "db", "update"],
            timeout_seconds=900,
            env={"GRYPE_DB_CACHE_DIR": str(settings.grype_db_cache_dir)},
        )
        now = _now_iso()
        if result.returncode != 0:
            err = _humanize_update_error(result.stderr or result.stdout, result.returncode)
            _set_state(
                {
                    "grype_db_last_update_at": now,
                    "grype_db_last_update_status": "error",
                    "grype_db_last_error": err[:2000],
                    "grype_db_last_check_at": now,
                }
            )
            logger.error("Grype DB update failed: %s", err[:500])
            return get_grype_db_status()

        status_result = run_command(
            [settings.grype_bin, "db", "status"],
            timeout_seconds=60,
            env={"GRYPE_DB_CACHE_DIR": str(settings.grype_db_cache_dir)},
        )
        parsed = parse_db_status_output(status_result.stdout + "\n" + status_result.stderr)
        _set_state(
            {
                "grype_db_built_at": parsed.get("built_at") or now,
                "grype_db_schema_version": parsed.get("schema_version"),
                "grype_db_last_update_at": now,
                "grype_db_last_update_status": "success",
                "grype_db_last_error": None,
                "grype_db_last_check_at": now,
            }
        )
        # Ready marker for healthchecks without importing SQLite in every probe
        ready_marker = settings.grype_db_cache_dir / ".ready"
        ready_marker.write_text(parsed.get("built_at") or now, encoding="utf-8")
        logger.info("Grype DB updated successfully")
    except Exception as exc:  # noqa: BLE001
        now = _now_iso()
        err = _humanize_update_error(str(exc))
        _set_state(
            {
                "grype_db_last_update_at": now,
                "grype_db_last_update_status": "error",
                "grype_db_last_error": err[:2000],
                "grype_db_last_check_at": now,
            }
        )
        logger.exception("Grype DB update raised")
    return get_grype_db_status()


def ensure_grype_db(*, wait_seconds: int = 900) -> GrypeDbStatus:
    """
    Ensure local Grype DB exists before accepting scan work.

    Uses a file lock so worker and scheduler do not download in parallel.
    """
    settings = get_settings()
    settings.grype_db_cache_dir.mkdir(parents=True, exist_ok=True)

    present, parsed = cli_db_present()
    if present:
        now = _now_iso()
        _set_state(
            {
                "grype_db_built_at": parsed.get("built_at") or _get_state().get("grype_db_built_at") or now,
                "grype_db_schema_version": parsed.get("schema_version"),
                "grype_db_last_check_at": now,
                "grype_db_last_update_status": _get_state().get("grype_db_last_update_status")
                or "success",
            }
        )
        ready_marker = settings.grype_db_cache_dir / ".ready"
        if not ready_marker.exists():
            ready_marker.write_text(parsed.get("built_at") or now, encoding="utf-8")
        return get_grype_db_status()

    lock_file = _lock_path()
    deadline = time.time() + wait_seconds
    fd = None
    try:
        fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o600)
        while True:
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                # Another process is bootstrapping — wait and re-check
                _set_state(
                    {
                        "grype_db_last_update_status": "updating",
                        "grype_db_last_check_at": _now_iso(),
                    }
                )
                logger.info("Waiting for Grype DB bootstrap lock held by another process")
                if time.time() > deadline:
                    _set_state(
                        {
                            "grype_db_last_update_status": "error",
                            "grype_db_last_error": NETWORK_HINT
                            + " Таймаут ожидания первичной загрузки.",
                        }
                    )
                    return get_grype_db_status()
                time.sleep(5)
                present, parsed = cli_db_present()
                if present:
                    return ensure_grype_db(wait_seconds=1)

        # Re-check under lock
        present, parsed = cli_db_present()
        if present:
            return ensure_grype_db(wait_seconds=1)

        logger.info("Bootstrapping Grype vulnerability database (first download may take minutes)")
        return update_grype_db()
    finally:
        if fd is not None:
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:  # noqa: BLE001
                pass
            os.close(fd)


def readiness_code() -> str:
    """
    ready | updating | not_ready | error
    """
    status = get_grype_db_status()
    if status.ready:
        return "ready"
    if status.last_update_status == "updating" or status.bootstrapping:
        return "updating"
    if status.last_update_status == "error":
        return "error"
    return "not_ready"
