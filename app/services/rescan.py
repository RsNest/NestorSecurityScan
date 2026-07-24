"""Auto-rescan of recent scans after a successful Grype DB update."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.database import session_scope
from app.models import Scan
from app.services.notifier import NotificationContext, get_notifier
from app.workers.queue import enqueue_scan

logger = logging.getLogger(__name__)


def enqueue_rescan_recent() -> int:
    """Re-enqueue scans finished in the last N days so they get rescanned
    with the freshly updated Grype DB. Returns number of scans enqueued.
    """
    settings = get_settings()
    if not settings.rescan_after_db_update:
        logger.info("Auto-rescan after DB update is disabled")
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.rescan_recent_days)
    enqueued = 0
    with session_scope() as session:
        candidates: list[Scan] = (
            session.query(Scan)
            .filter(
                Scan.finished_at.isnot(None),
                Scan.finished_at >= cutoff,
                Scan.requested_image.isnot(None),
            )
            .order_by(Scan.finished_at.desc())
            .limit(500)
            .all()
        )
        items = [(s.id, s.requested_image) for s in candidates]
    for _id, image in items:
        try:
            enqueue_scan(
                image=image,
                source="rescan",
                parent_scan_id=_id,
                rescan=True,
            )
            enqueued += 1
        except Exception:  # noqa: BLE001
            logger.exception("Failed to enqueue rescan for %s", image)
    logger.info("Auto-rescan enqueued %s scans (window=%sd)", enqueued, settings.rescan_recent_days)
    return enqueued


def notify_completed(scan: Scan) -> None:
    """Fire-and-forget notification for a finished scan."""
    try:
        ctx = NotificationContext(
            scan_id=scan.id,
            image=scan.canonical_image or scan.requested_image,
            status=scan.status,
            critical=scan.critical_count,
            high=scan.high_count,
            kev=scan.kev_count,
        )
        get_notifier().send(ctx)
    except Exception:  # noqa: BLE001
        logger.exception("Notifier dispatch failed for %s", scan.id)
