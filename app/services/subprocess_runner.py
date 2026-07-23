"""Safe subprocess helpers for Syft and Grype."""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings
from app.errors import ToolExecutionError, ToolTimeoutError, map_subprocess_error
from app.logging_setup import mask_secrets

logger = logging.getLogger(__name__)

MAX_LOG_CHARS = 50_000


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(
    args: list[str],
    *,
    timeout_seconds: int,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    scan_id: str | None = None,
) -> CommandResult:
    if not args:
        raise ToolExecutionError("Пустая команда.")
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    settings = get_settings()
    merged_env.setdefault("GRYPE_DB_CACHE_DIR", str(settings.grype_db_cache_dir))
    if settings.grype_db_auto_update:
        merged_env.setdefault("GRYPE_DB_AUTO_UPDATE", "true")
    else:
        merged_env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")

    logger.info(
        "Running command: %s",
        mask_secrets(" ".join(args)),
        extra={"scan_id": scan_id},
    )
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=merged_env,
            cwd=str(cwd) if cwd else None,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeoutError(
            f"Превышен таймаут {timeout_seconds}с для {args[0]}."
        ) from exc
    except FileNotFoundError as exc:
        raise ToolExecutionError(f"Утилита не найдена: {args[0]}") from exc

    stdout = (completed.stdout or "")[:MAX_LOG_CHARS]
    stderr = (completed.stderr or "")[:MAX_LOG_CHARS]
    return CommandResult(returncode=completed.returncode, stdout=stdout, stderr=stderr)


def require_success(result: CommandResult, tool: str) -> CommandResult:
    if result.returncode != 0:
        raise map_subprocess_error(tool, result.stderr or result.stdout, result.returncode)
    return result
