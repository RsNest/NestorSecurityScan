"""Harbor discovery of new images for periodic scanning."""

from __future__ import annotations

import logging

from app.config import get_settings
from app.database import session_scope
from app.errors import HarborError
from app.models import Scan
from app.services.harbor_client import HarborClient
from app.services.policy_engine import load_policy
from app.workers.queue import enqueue_scan

logger = logging.getLogger(__name__)


def discover_and_enqueue() -> int:
    settings = get_settings()
    if not settings.discovery_enabled or not settings.harbor_enabled:
        return 0
    try:
        client = HarborClient(settings)
    except HarborError as exc:
        logger.warning("Discovery skipped: %s", exc.message)
        return 0

    _, policy_sha = load_policy(settings.policy_file)
    projects = client.list_projects()
    filters = set(settings.harbor_project_filters)
    enqueued = 0

    for project in projects:
        name = project.get("name")
        if not name:
            continue
        if filters and name not in filters:
            continue
        try:
            repos = client.list_repositories(name)
        except HarborError as exc:
            logger.warning("Skip project %s: %s", name, exc.message)
            continue
        for repo in repos:
            repo_name = repo.get("name") or ""
            # Harbor returns name as project/repo
            short = repo_name
            if repo_name.startswith(f"{name}/"):
                short = repo_name[len(name) + 1 :]
            try:
                artifacts = client.list_artifacts(name, short)
            except HarborError as exc:
                logger.warning("Skip repo %s: %s", repo_name, exc.message)
                continue
            for artifact in artifacts:
                digest = artifact.get("digest")
                if not digest:
                    continue
                with session_scope() as session:
                    exists = (
                        session.query(Scan)
                        .filter(Scan.digest == digest, Scan.status.notin_(["ERROR", "CANCELLED"]))
                        .first()
                    )
                    if exists:
                        continue
                image_ref = client.artifact_to_image_ref(name, short, artifact)
                if not image_ref:
                    continue
                tags = artifact.get("tags") or []
                tag = tags[0].get("name") if tags else None
                # Prefer tag ref if available, else digest
                host = settings.harbor_url.replace("https://", "").replace("http://", "").split("/")[0]
                full_repo = f"{name}/{short}"
                requested = (
                    f"{host}/{full_repo}:{tag}" if tag else f"{host}/{full_repo}@{digest}"
                )
                enqueue_scan(
                    image=requested,
                    source="scheduler",
                    skip_dedup=False,
                )
                enqueued += 1
                logger.info("Discovery enqueued %s", requested)
    return enqueued
