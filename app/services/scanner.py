"""Main scan orchestration pipeline."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.database import session_scope
from app.errors import ScannerError
from app.models import ACTIVE_SCAN_STATUSES, Scan, utcnow
from app.services.grype_db import get_grype_db_status
from app.services.grype_runner import (
    get_grype_version,
    load_grype_json,
    normalize_grype_json,
    run_grype_on_sbom,
)
from app.services.image_ref import parse_image_reference
from app.services.policy_engine import apply_policy, load_policy
from app.services.registry_auth import temporary_docker_auth
from app.services.report_generator import (
    append_scan_log,
    create_report_dir,
    generate_html_report,
    write_metadata,
    write_normalized_report,
)
from app.services.syft_runner import generate_sbom, get_syft_version

logger = logging.getLogger(__name__)


def update_scan(scan_id: str, **fields: Any) -> None:
    """Short transaction update for scan progress."""
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        for key, value in fields.items():
            if hasattr(scan, key):
                setattr(scan, key, value)


def is_cancel_requested(scan_id: str) -> bool:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        return bool(scan and scan.cancel_requested)


def find_active_duplicate(digest: str | None, policy_hash: str | None) -> Scan | None:
    if not digest or not policy_hash:
        return None
    with session_scope() as session:
        return (
            session.query(Scan)
            .filter(
                Scan.digest == digest,
                Scan.policy_hash == policy_hash,
                Scan.status.in_(ACTIVE_SCAN_STATUSES),
            )
            .first()
        )


def _check_cancel(scan_id: str) -> None:
    if is_cancel_requested(scan_id):
        update_scan(
            scan_id,
            status="CANCELLED",
            stage="CANCELLED",
            progress=100,
            message="Отменено пользователем",
            finished_at=utcnow(),
        )
        raise ScannerError("Сканирование отменено")


def run_full_scan(
    scan_id: str,
    *,
    registry_username: str | None = None,
    registry_password: str | None = None,
) -> None:
    settings = get_settings()
    timeout = settings.scan_timeout_minutes * 60
    report_dir = create_report_dir(scan_id)

    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ScannerError(f"Scan {scan_id} не найден")
        requested = scan.requested_image
        platform = scan.platform
        policy_path = Path(settings.policy_file)

    update_scan(
        scan_id,
        status="RESOLVING_IMAGE",
        stage="RESOLVING_IMAGE",
        progress=5,
        message="Разбор ссылки на образ",
        started_at=utcnow(),
    )
    append_scan_log(scan_id, f"Resolving image: {requested}")
    _check_cancel(scan_id)

    ref = parse_image_reference(requested)
    update_scan(
        scan_id,
        registry=ref.registry,
        repository=ref.repository,
        tag=ref.tag,
        digest=ref.digest,
        canonical_image=ref.reference_for_scan,
    )

    try:
        policy, p_hash = load_policy(policy_path)
    except Exception as exc:
        update_scan(
            scan_id,
            status="ERROR",
            stage="ERROR",
            progress=100,
            error_message=str(exc),
            message=str(exc),
            finished_at=utcnow(),
        )
        raise

    update_scan(scan_id, policy_name=policy.name, policy_hash=p_hash)
    syft_ver = get_syft_version()
    grype_ver = get_grype_version()
    db_status = get_grype_db_status()
    update_scan(
        scan_id,
        syft_version=syft_ver,
        grype_version=grype_ver,
        grype_db_built_at=db_status.built_at,
    )

    username = registry_username or (
        settings.harbor_username if settings.harbor_enabled else None
    )
    password = registry_password or (
        settings.harbor_password if settings.harbor_enabled else None
    )

    try:
        with temporary_docker_auth(scan_id, ref.registry, username, password) as env:
            _check_cancel(scan_id)
            update_scan(
                scan_id,
                status="GENERATING_SBOM",
                stage="GENERATING_SBOM",
                progress=20,
                message="Генерация SBOM (Syft)",
            )
            append_scan_log(scan_id, f"Syft scan: {ref.reference_for_scan}")
            syft_json, _cyclonedx, syft_log = generate_sbom(
                ref.reference_for_scan,
                report_dir,
                timeout_seconds=timeout,
                env=env,
                platform=platform,
                scan_id=scan_id,
            )
            append_scan_log(scan_id, syft_log[:5000])

            # Try extract digest from syft SBOM if missing
            digest = ref.digest
            try:
                sbom = json.loads(syft_json.read_text(encoding="utf-8"))
                source = sbom.get("source") or {}
                target = source.get("target") or {}
                image_id = None
                if isinstance(target, dict):
                    image_id = (
                        target.get("repoDigests")
                        or target.get("manifestDigest")
                        or target.get("imageID")
                    )
                    if isinstance(image_id, list) and image_id:
                        # repoDigests like registry/repo@sha256:...
                        for item in image_id:
                            if "@sha256:" in str(item):
                                digest = "sha256:" + str(item).split("@sha256:", 1)[1]
                                break
                    elif isinstance(image_id, str) and image_id.startswith("sha256:"):
                        digest = image_id
                if digest:
                    ref = ref.with_digest(digest) if not ref.digest else ref
                    update_scan(
                        scan_id,
                        digest=digest,
                        canonical_image=ref.reference_for_scan,
                    )
            except Exception:  # noqa: BLE001
                logger.debug("Could not extract digest from SBOM", exc_info=True)

            _check_cancel(scan_id)
            update_scan(
                scan_id,
                status="SCANNING",
                stage="SCANNING",
                progress=55,
                message="Поиск уязвимостей (Grype)",
            )
            grype_path = report_dir / "grype.json"
            grype_log = run_grype_on_sbom(
                syft_json,
                grype_path,
                timeout_seconds=timeout,
                env=env,
                scan_id=scan_id,
            )
            append_scan_log(scan_id, grype_log[:5000])

            _finalize_from_grype(
                scan_id,
                report_dir=report_dir,
                grype_path=grype_path,
                policy=policy,
                p_hash=p_hash,
                requested=requested,
                canonical=ref.reference_for_scan,
                digest=digest,
                syft_ver=syft_ver,
                grype_ver=grype_ver,
                db_built=db_status.built_at,
                source_hint=None,
            )
    except ScannerError as exc:
        if "отменено" in str(exc).lower():
            return
        update_scan(
            scan_id,
            status="ERROR",
            stage="ERROR",
            progress=100,
            error_message=exc.message,
            message=exc.message,
            finished_at=utcnow(),
        )
        append_scan_log(scan_id, f"ERROR: {exc.message}")
        write_metadata(
            scan_id,
            {
                "scan_id": scan_id,
                "status": "ERROR",
                "error_message": exc.message,
                "requested_image": requested,
            },
        )
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        update_scan(
            scan_id,
            status="ERROR",
            stage="ERROR",
            progress=100,
            error_message=msg,
            message=msg,
            finished_at=utcnow(),
        )
        append_scan_log(scan_id, f"ERROR: {msg}")


def run_rescan(scan_id: str, parent_scan_id: str) -> None:
    """Rescan existing SBOM with current Grype DB — bypasses image pull/Syft."""
    settings = get_settings()
    timeout = settings.scan_timeout_minutes * 60
    report_dir = create_report_dir(scan_id)
    parent_dir = create_report_dir(parent_scan_id)
    parent_sbom = parent_dir / "sbom.syft.json"
    if not parent_sbom.exists():
        update_scan(
            scan_id,
            status="ERROR",
            error_message="SBOM родителя не найден",
            finished_at=utcnow(),
        )
        return

    shutil.copy2(parent_sbom, report_dir / "sbom.syft.json")
    parent_cdx = parent_dir / "sbom.cyclonedx.json"
    if parent_cdx.exists():
        shutil.copy2(parent_cdx, report_dir / "sbom.cyclonedx.json")

    with session_scope() as session:
        parent = session.get(Scan, parent_scan_id)
        scan = session.get(Scan, scan_id)
        if not parent or not scan:
            return
        requested = parent.requested_image
        canonical = parent.canonical_image
        digest = parent.digest
        update_scan(
            scan_id,
            requested_image=requested,
            canonical_image=canonical,
            digest=digest,
            registry=parent.registry,
            repository=parent.repository,
            tag=parent.tag,
            started_at=utcnow(),
            status="SCANNING",
            stage="SCANNING",
            progress=40,
            message="Rescan SBOM текущей базой Grype",
        )

    policy, p_hash = load_policy(Path(settings.policy_file))
    syft_ver = get_syft_version()
    grype_ver = get_grype_version()
    db_status = get_grype_db_status()
    update_scan(
        scan_id,
        policy_name=policy.name,
        policy_hash=p_hash,
        syft_version=syft_ver,
        grype_version=grype_ver,
        grype_db_built_at=db_status.built_at,
    )

    try:
        grype_path = report_dir / "grype.json"
        run_grype_on_sbom(
            report_dir / "sbom.syft.json",
            grype_path,
            timeout_seconds=timeout,
            scan_id=scan_id,
        )
        _finalize_from_grype(
            scan_id,
            report_dir=report_dir,
            grype_path=grype_path,
            policy=policy,
            p_hash=p_hash,
            requested=requested,
            canonical=canonical or requested,
            digest=digest,
            syft_ver=syft_ver,
            grype_ver=grype_ver,
            db_built=db_status.built_at,
            source_hint="rescan",
        )
    except Exception as exc:  # noqa: BLE001
        update_scan(
            scan_id,
            status="ERROR",
            error_message=str(exc),
            message=str(exc),
            finished_at=utcnow(),
        )


def _finalize_from_grype(
    scan_id: str,
    *,
    report_dir: Path,
    grype_path: Path,
    policy,
    p_hash: str,
    requested: str,
    canonical: str,
    digest: str | None,
    syft_ver: str | None,
    grype_ver: str | None,
    db_built: str | None,
    source_hint: str | None,
) -> None:
    _check_cancel(scan_id)
    update_scan(
        scan_id,
        status="APPLYING_POLICY",
        stage="APPLYING_POLICY",
        progress=75,
        message="Применение политики",
    )
    grype_data = load_grype_json(grype_path)
    vulns, counts, stats = normalize_grype_json(
        grype_data,
        high_epss_threshold=policy.epss.minimum_probability if policy.epss.enabled else 0.70,
    )
    annotated, policy_result = apply_policy(vulns, counts, policy, p_hash)

    update_scan(
        scan_id,
        status="GENERATING_REPORT",
        stage="GENERATING_REPORT",
        progress=90,
        message="Формирование отчёта",
    )
    finished = utcnow()
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        source = source_hint or (scan.source if scan else "manual")
        created = scan.created_at if scan else finished

    metadata = {
        "scan_id": scan_id,
        "source": source,
        "requested_image": requested,
        "canonical_image": canonical,
        "digest": digest,
        "status": policy_result.status,
        "created_at": created.isoformat() if created else None,
        "started_at": None,
        "finished_at": finished.isoformat(),
        "syft_version": syft_ver,
        "grype_version": grype_ver,
        "grype_database_built_at": db_built,
        "policy_name": policy_result.policy_name,
        "policy_hash": policy_result.policy_hash,
    }
    write_metadata(scan_id, metadata)
    write_normalized_report(
        scan_id,
        metadata=metadata,
        counts=counts,
        stats=stats,
        vulns=annotated,
        policy_result=policy_result,
    )
    generate_html_report(
        scan_id,
        metadata=metadata,
        counts=counts,
        stats=stats,
        vulns=annotated,
        policy_result=policy_result,
    )
    append_scan_log(scan_id, f"Completed with status {policy_result.status}")

    update_scan(
        scan_id,
        status=policy_result.status,
        stage=policy_result.status,
        progress=100,
        message="Готово",
        finished_at=finished,
        critical_count=counts.critical,
        high_count=counts.high,
        medium_count=counts.medium,
        low_count=counts.low,
        negligible_count=counts.negligible,
        unknown_count=counts.unknown,
        total_vulns=stats["total"],
        unique_cve_count=stats["unique_cve"],
        fixable_count=stats["fixable"],
        unfixable_count=stats["unfixable"],
        kev_count=stats["kev"],
        high_epss_count=stats["high_epss"],
        error_message=None,
    )
