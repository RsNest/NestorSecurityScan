"""Temporary Docker config for private registry authentication."""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from app.config import get_settings
from app.services.image_ref import registry_host

logger = logging.getLogger(__name__)


def create_docker_config(
    scan_id: str,
    registry: str,
    username: str | None,
    password: str | None,
) -> Path | None:
    """Create DOCKER_CONFIG dir with 0700/0600 perms. Returns dir path or None."""
    if not username or password is None:
        return None

    settings = get_settings()
    base = settings.auth_tmp_dir / scan_id
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, mode=0o700)
    os.chmod(base, 0o700)

    host = registry_host(registry)
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    config = {"auths": {host: {"auth": token}}}
    config_path = base / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(config_path, 0o600)
    return base


def cleanup_docker_config(scan_id: str) -> None:
    settings = get_settings()
    path = settings.auth_tmp_dir / scan_id
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
        logger.info("Removed temporary registry credentials", extra={"scan_id": scan_id})


@contextmanager
def temporary_docker_auth(
    scan_id: str,
    registry: str,
    username: str | None,
    password: str | None,
) -> Generator[dict[str, str], None, None]:
    """Yield env updates with DOCKER_CONFIG; always clean up afterwards."""
    env_updates: dict[str, str] = {}
    config_dir = create_docker_config(scan_id, registry, username, password)
    try:
        if config_dir is not None:
            env_updates["DOCKER_CONFIG"] = str(config_dir)
        yield env_updates
    finally:
        cleanup_docker_config(scan_id)
