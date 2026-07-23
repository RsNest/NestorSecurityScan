"""RQ task definitions."""

from __future__ import annotations

import logging

from app.database import init_db
from app.logging_setup import setup_logging
from app.services.scanner import run_full_scan, run_rescan

logger = logging.getLogger(__name__)


def execute_scan(
    scan_id: str,
    registry_username: str | None = None,
    registry_password: str | None = None,
) -> None:
    setup_logging("worker")
    init_db()
    logger.info("Starting scan", extra={"scan_id": scan_id})
    run_full_scan(
        scan_id,
        registry_username=registry_username,
        registry_password=registry_password,
    )


def execute_rescan(scan_id: str, parent_scan_id: str) -> None:
    setup_logging("worker")
    init_db()
    logger.info(
        "Starting rescan",
        extra={"scan_id": scan_id},
    )
    run_rescan(scan_id, parent_scan_id)
