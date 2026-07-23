"""Grype vulnerability scanning and result normalization."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.errors import ToolExecutionError
from app.schemas import NormalizedVulnerability, SeverityCounts
from app.services.subprocess_runner import require_success, run_command

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def get_grype_version() -> str | None:
    settings = get_settings()
    result = run_command([settings.grype_bin, "version"], timeout_seconds=30)
    if result.returncode != 0:
        return None
    match = _VERSION_RE.search(result.stdout or result.stderr)
    return match.group(1) if match else (result.stdout.strip()[:64] or None)


def run_grype_on_sbom(
    syft_sbom: Path,
    output_path: Path,
    *,
    timeout_seconds: int,
    env: dict[str, str] | None = None,
    scan_id: str | None = None,
) -> str:
    if not syft_sbom.exists():
        raise ToolExecutionError("Повреждённый SBOM: файл Syft не найден.")
    settings = get_settings()
    args = [
        settings.grype_bin,
        f"sbom:{syft_sbom}",
        "-o",
        "json",
        "--file",
        str(output_path),
    ]
    result = run_command(
        args,
        timeout_seconds=timeout_seconds,
        env=env,
        cwd=output_path.parent,
        scan_id=scan_id,
    )
    require_success(result, "Grype")
    if not output_path.exists():
        raise ToolExecutionError("Grype не создал файл результатов.")
    return (result.stdout + "\n" + result.stderr).strip()


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_epss(vuln: dict[str, Any], match: dict[str, Any]) -> float | None:
    for source in (vuln, match, match.get("vulnerability") or {}):
        if not isinstance(source, dict):
            continue
        epss = source.get("epss")
        if isinstance(epss, list) and epss:
            score = epss[0].get("epss") if isinstance(epss[0], dict) else None
            parsed = _as_float(score)
            if parsed is not None:
                return parsed
        if isinstance(epss, dict):
            parsed = _as_float(epss.get("epss") or epss.get("score"))
            if parsed is not None:
                return parsed
        parsed = _as_float(source.get("epssScore") or source.get("EPSS"))
        if parsed is not None:
            return parsed
    return None


def _extract_kev(vuln: dict[str, Any], match: dict[str, Any]) -> bool:
    for source in (vuln, match, match.get("vulnerability") or {}):
        if not isinstance(source, dict):
            continue
        if source.get("kev") is True or source.get("isKev") is True:
            return True
        known = source.get("knownExploited") or source.get("known_exploited")
        if known:
            return True
        related = source.get("relatedVulnerabilities") or []
        for item in related:
            if isinstance(item, dict) and (item.get("kev") or item.get("knownExploited")):
                return True
    return False


def normalize_grype_json(
    grype_data: dict[str, Any],
    *,
    high_epss_threshold: float = 0.70,
) -> tuple[list[NormalizedVulnerability], SeverityCounts, dict[str, int]]:
    matches = grype_data.get("matches") or []
    vulns: list[NormalizedVulnerability] = []
    counts = SeverityCounts()
    unique_ids: set[str] = set()
    fixable = 0
    unfixable = 0
    kev_count = 0
    high_epss = 0

    for match in matches:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        severity = (vuln.get("severity") or "Unknown").capitalize()
        if severity.lower() == "negligible":
            severity = "Negligible"
        elif severity.lower() == "unknown":
            severity = "Unknown"
        else:
            severity = severity.capitalize()

        fix = vuln.get("fix") or {}
        fixed_versions = fix.get("versions") if isinstance(fix, dict) else None
        fixed_version = None
        if isinstance(fixed_versions, list) and fixed_versions:
            fixed_version = ", ".join(str(v) for v in fixed_versions)
            fixable += 1
        else:
            state = (fix.get("state") if isinstance(fix, dict) else None) or ""
            if str(state).lower() in {"fixed", "wont-fix"}:
                if str(state).lower() == "fixed":
                    fixable += 1
                else:
                    unfixable += 1
            else:
                unfixable += 1

        epss = _extract_epss(vuln, match)
        kev = _extract_kev(vuln, match)
        if kev:
            kev_count += 1
        if epss is not None and epss >= high_epss_threshold:
            high_epss += 1

        vuln_id = str(vuln.get("id") or "UNKNOWN")
        unique_ids.add(vuln_id)
        urls = list(vuln.get("urls") or [])
        if vuln.get("dataSource"):
            urls.append(str(vuln["dataSource"]))

        locations = artifact.get("locations") or []
        package_path = None
        if locations and isinstance(locations[0], dict):
            package_path = locations[0].get("path")

        item = NormalizedVulnerability(
            id=vuln_id,
            severity=severity,
            package_name=artifact.get("name"),
            installed_version=artifact.get("version"),
            fixed_version=fixed_version,
            package_type=artifact.get("type"),
            package_path=package_path,
            data_source=vuln.get("dataSource"),
            namespace=vuln.get("namespace"),
            description=vuln.get("description"),
            urls=[u for u in urls if u],
            epss=epss,
            kev=kev,
            risk_score=_as_float(vuln.get("risk") or match.get("risk")),
        )
        vulns.append(item)

        key = severity.lower()
        if key == "critical":
            counts.critical += 1
        elif key == "high":
            counts.high += 1
        elif key == "medium":
            counts.medium += 1
        elif key == "low":
            counts.low += 1
        elif key == "negligible":
            counts.negligible += 1
        else:
            counts.unknown += 1

    stats = {
        "total": len(vulns),
        "unique_cve": len(unique_ids),
        "fixable": fixable,
        "unfixable": unfixable,
        "kev": kev_count,
        "high_epss": high_epss,
    }
    return vulns, counts, stats


def load_grype_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ToolExecutionError("Повреждённый JSON отчёт Grype.") from exc
