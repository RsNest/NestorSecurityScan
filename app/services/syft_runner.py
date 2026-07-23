"""Syft SBOM generation."""

from __future__ import annotations

import re
from pathlib import Path

from app.config import get_settings
from app.services.subprocess_runner import require_success, run_command

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def get_syft_version() -> str | None:
    settings = get_settings()
    result = run_command([settings.syft_bin, "version"], timeout_seconds=30)
    if result.returncode != 0:
        return None
    match = _VERSION_RE.search(result.stdout or result.stderr)
    return match.group(1) if match else (result.stdout.strip()[:64] or None)


def generate_sbom(
    image_reference: str,
    report_dir: Path,
    *,
    timeout_seconds: int,
    env: dict[str, str] | None = None,
    platform: str | None = None,
    scan_id: str | None = None,
) -> tuple[Path, Path, str]:
    settings = get_settings()
    syft_json = report_dir / "sbom.syft.json"
    cyclonedx = report_dir / "sbom.cyclonedx.json"
    args = [
        settings.syft_bin,
        image_reference,
        "-o",
        f"syft-json={syft_json}",
        "-o",
        f"cyclonedx-json={cyclonedx}",
    ]
    if platform:
        args.extend(["--platform", platform])

    result = run_command(
        args,
        timeout_seconds=timeout_seconds,
        env=env,
        cwd=report_dir,
        scan_id=scan_id,
    )
    require_success(result, "Syft")
    if not syft_json.exists() or syft_json.stat().st_size == 0:
        raise RuntimeError("Повреждённый или пустой SBOM Syft.")
    log = (result.stdout + "\n" + result.stderr).strip()
    return syft_json, cyclonedx, log
