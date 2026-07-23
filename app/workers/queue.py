"""RQ queue helpers."""

from __future__ import annotations

import logging

from redis import Redis
from rq import Queue
from rq.job import Job

from app.config import get_settings
from app.database import session_scope
from app.models import Scan, new_scan_id, utcnow
from app.services.image_ref import parse_image_reference
from app.services.policy_engine import load_policy
from app.services.scanner import find_active_duplicate

logger = logging.getLogger(__name__)

QUEUE_NAME = "scans"


def get_redis() -> Redis:
    return Redis.from_url(get_settings().redis_url)


def get_queue() -> Queue:
    settings = get_settings()
    return Queue(
        QUEUE_NAME,
        connection=get_redis(),
        default_timeout=settings.scan_timeout_minutes * 60,
    )


def enqueue_scan(
    *,
    image: str,
    source: str = "manual",
    registry_username: str | None = None,
    registry_password: str | None = None,
    platform: str | None = None,
    webhook_event_id: str | None = None,
    skip_dedup: bool = False,
    parent_scan_id: str | None = None,
    rescan: bool = False,
) -> tuple[Scan, bool]:
    """
    Create scan row and enqueue RQ job.
    Returns (scan, created).
    Rescan always bypasses digest/policy dedup.
    """
    settings = get_settings()
    ref = parse_image_reference(image)
    try:
        _policy, p_hash = load_policy(settings.policy_file)
    except Exception:
        p_hash = None

    if not rescan and not skip_dedup and ref.digest and p_hash:
        existing = find_active_duplicate(ref.digest, p_hash)
        if existing:
            return existing, False

    if webhook_event_id:
        with session_scope() as session:
            dup = (
                session.query(Scan)
                .filter(Scan.webhook_event_id == webhook_event_id)
                .first()
            )
            if dup:
                session.expunge(dup)
                return dup, False

    scan_id = new_scan_id()
    with session_scope() as session:
        scan = Scan(
            id=scan_id,
            source="rescan" if rescan else source,
            requested_image=image,
            canonical_image=ref.reference_for_scan,
            registry=ref.registry,
            repository=ref.repository,
            tag=ref.tag,
            digest=ref.digest,
            status="QUEUED",
            stage="QUEUED",
            progress=0,
            message="В очереди",
            platform=platform,
            policy_hash=p_hash,
            webhook_event_id=webhook_event_id,
            parent_scan_id=parent_scan_id,
            created_at=utcnow(),
        )
        session.add(scan)

    queue = get_queue()
    if rescan and parent_scan_id:
        job = queue.enqueue(
            "app.workers.tasks.execute_rescan",
            scan_id,
            parent_scan_id,
            job_id=scan_id,
            job_timeout=settings.scan_timeout_minutes * 60,
            result_ttl=86400,
            failure_ttl=86400,
        )
    else:
        job = queue.enqueue(
            "app.workers.tasks.execute_scan",
            scan_id,
            registry_username,
            registry_password,
            job_id=scan_id,
            job_timeout=settings.scan_timeout_minutes * 60,
            result_ttl=86400,
            failure_ttl=86400,
        )

    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        scan.rq_job_id = job.id
        session.flush()
        session.refresh(scan)
        session.expunge(scan)
        return scan, True


def cancel_job(scan_id: str) -> bool:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return False
        scan.cancel_requested = 1
        if scan.status == "QUEUED":
            scan.status = "CANCELLED"
            scan.stage = "CANCELLED"
            scan.progress = 100
            scan.message = "Отменено"
            scan.finished_at = utcnow()
    try:
        job = Job.fetch(scan_id, connection=get_redis())
        job.cancel()
    except Exception:  # noqa: BLE001
        logger.debug("RQ job cancel failed for %s", scan_id, exc_info=True)
    return True
