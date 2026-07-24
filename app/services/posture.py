"""Aggregated Security Posture metrics for the dashboard."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from app.database import session_scope
from app.models import TERMINAL_STATUSES, Scan


def security_posture(window_days: int = 7) -> dict:
    """Return dashboard-friendly aggregate stats."""
    now = datetime.now(UTC)
    window_start = now - timedelta(days=window_days)
    # SQLite returns naive datetimes; normalise to UTC-naive for comparison
    if now.tzinfo is not None:
        window_start_naive = window_start.replace(tzinfo=None)
    else:
        window_start_naive = window_start
    with session_scope() as session:
        all_scans = session.query(Scan).all()
        total = len(all_scans)
        by_status: Counter[str] = Counter(s.status for s in all_scans)
        kev_total = sum(s.kev_count for s in all_scans)
        critical_total = sum(s.critical_count for s in all_scans)
        high_total = sum(s.high_count for s in all_scans)

        recent = [
            s
            for s in all_scans
            if s.created_at
            and (s.created_at.replace(tzinfo=None) if s.created_at.tzinfo else s.created_at)
            >= window_start_naive
        ]
        new_cves = sum(s.unique_cve_count for s in recent if s.status in TERMINAL_STATUSES)

        # Trend buckets per day, last window_days
        per_day: dict[str, dict[str, int]] = {}
        for d in range(window_days):
            day = (now - timedelta(days=d)).date().isoformat()
            per_day[day] = {"scans": 0, "non_compliant": 0}

        for s in all_scans:
            if not s.created_at:
                continue
            dt = s.created_at.replace(tzinfo=None) if s.created_at.tzinfo else s.created_at
            day = dt.date().isoformat()
            if day in per_day:
                per_day[day]["scans"] += 1
                if s.status == "NON_COMPLIANT":
                    per_day[day]["non_compliant"] += 1

        top_vuln = (
            session.query(Scan)
            .filter(Scan.status == "NON_COMPLIANT")
            .order_by((Scan.critical_count + Scan.high_count).desc())
            .limit(5)
            .all()
        )
        for s in top_vuln:
            session.expunge(s)

    trend = [{"date": d, **v} for d, v in sorted(per_day.items())]
    return {
        "total": total,
        "compliant": by_status.get("COMPLIANT", 0) + by_status.get("COMPLIANT_WITH_EXCEPTIONS", 0),
        "non_compliant": by_status.get("NON_COMPLIANT", 0),
        "error": by_status.get("ERROR", 0),
        "running": by_status.get("QUEUED", 0)
        + by_status.get("RESOLVING_IMAGE", 0)
        + by_status.get("GENERATING_SBOM", 0)
        + by_status.get("SCANNING", 0)
        + by_status.get("APPLYING_POLICY", 0)
        + by_status.get("GENERATING_REPORT", 0),
        "kev_total": kev_total,
        "critical_total": critical_total,
        "high_total": high_total,
        "new_cves_window": new_cves,
        "trend": trend,
        "top_vulnerable": [
            {
                "id": s.id,
                "image": s.requested_image,
                "critical": s.critical_count,
                "high": s.high_count,
                "kev": s.kev_count,
                "status": s.status,
            }
            for s in top_vuln
        ],
    }
