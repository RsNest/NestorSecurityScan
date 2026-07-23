"""APScheduler process: discovery, Grype DB update, retention cleanup."""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apscheduler.schedulers.blocking import BlockingScheduler

from app.config import get_settings
from app.database import init_db, session_scope
from app.logging_setup import setup_logging
from app.models import Scan
from app.services.discovery import discover_and_enqueue
from app.services.grype_db import ensure_grype_db, update_grype_db
from app.services.report_generator import delete_report_dir

logger = logging.getLogger(__name__)


def job_discovery() -> None:
    try:
        n = discover_and_enqueue()
        logger.info("Discovery finished, enqueued=%s", n)
    except Exception:  # noqa: BLE001
        logger.exception("Discovery failed")


def job_grype_db_update() -> None:
    try:
        status = update_grype_db()
        logger.info(
            "Grype DB update status=%s built_at=%s",
            status.last_update_status,
            status.built_at,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Grype DB update job failed")


def job_retention() -> None:
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.report_retention_days)
    try:
        with session_scope() as session:
            old = (
                session.query(Scan)
                .filter(Scan.created_at < cutoff)
                .all()
            )
            ids = [s.id for s in old]
            for scan in old:
                session.delete(scan)
        for scan_id in ids:
            try:
                delete_report_dir(scan_id)
            except Exception:  # noqa: BLE001
                logger.warning("Failed to delete report %s", scan_id)
        if ids:
            logger.info("Retention removed %s scans", len(ids))
    except Exception:  # noqa: BLE001
        logger.exception("Retention job failed")


def main() -> None:
    setup_logging("scheduler")
    settings = get_settings()
    settings.ensure_dirs()
    init_db()
    scheduler = BlockingScheduler(timezone="UTC")

    if settings.discovery_enabled:
        scheduler.add_job(
            job_discovery,
            "interval",
            minutes=max(1, settings.discovery_interval_minutes),
            id="discovery",
            max_instances=1,
            coalesce=True,
        )
        logger.info(
            "Discovery enabled every %s minutes",
            settings.discovery_interval_minutes,
        )

    scheduler.add_job(
        job_grype_db_update,
        "interval",
        hours=max(1, settings.grype_db_update_interval_hours),
        id="grype_db_update",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        job_retention,
        "interval",
        hours=24,
        id="retention",
        max_instances=1,
        coalesce=True,
    )

    # Bootstrap / wait for Grype DB before scheduling (shares lock with worker)
    try:
        status = ensure_grype_db(wait_seconds=900)
        logger.info(
            "Grype DB bootstrap status=%s built_at=%s",
            status.last_update_status,
            status.built_at,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Initial Grype DB bootstrap failed")

    logger.info("Scheduler started")
    scheduler.start()


if __name__ == "__main__":
    main()
