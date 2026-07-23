"""RQ worker process entrypoint."""

from __future__ import annotations

import logging
import sys

from redis import Redis
from rq import Worker

from app.config import get_settings
from app.database import init_db
from app.logging_setup import setup_logging
from app.services.grype_db import ensure_grype_db, is_grype_db_ready
from app.workers.queue import QUEUE_NAME

logger = logging.getLogger(__name__)


def main() -> None:
    setup_logging("worker")
    settings = get_settings()
    settings.ensure_dirs()
    init_db()

    logger.info(
        "Ensuring Grype vulnerability database is ready "
        "(first start may download ~1GB and take several minutes)"
    )
    status = ensure_grype_db(wait_seconds=900)
    if not status.ready and not is_grype_db_ready():
        logger.error(
            "Grype DB is not ready: %s",
            status.last_error or status.last_update_status,
        )
        # Still start worker so queued jobs can retry after manual make update-db,
        # but healthcheck will stay unhealthy until DB appears.
        logger.warning(
            "Worker will start, but scans may fail until the vulnerability DB is available"
        )
    else:
        logger.info("Grype DB ready (built_at=%s)", status.built_at)

    redis_conn = Redis.from_url(settings.redis_url)
    logger.info("Worker starting (accepting scan jobs)")
    worker = Worker(
        [QUEUE_NAME],
        connection=redis_conn,
        name="scanner-worker",
    )
    worker.work(with_scheduler=False, logging_level=settings.log_level.upper())


def healthcheck_main() -> None:
    """Exit 0 only when Redis is up and Grype DB is ready."""
    settings = get_settings()
    try:
        Redis.from_url(settings.redis_url).ping()
    except Exception:  # noqa: BLE001
        sys.exit(1)
    ready_marker = settings.grype_db_cache_dir / ".ready"
    if ready_marker.exists() or is_grype_db_ready():
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "healthcheck":
        healthcheck_main()
    else:
        main()
