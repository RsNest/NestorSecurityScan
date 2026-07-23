"""Report directory and HTML escaping tests."""

import uuid
from pathlib import Path

import pytest

from app.config import get_settings
from app.schemas import NormalizedVulnerability, PolicyResult, SeverityCounts
from app.services.report_generator import (
    create_report_dir,
    generate_html_report,
    safe_report_dir,
)


def test_safe_report_dir_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    settings = get_settings()
    settings.reports_dir = tmp_path
    with pytest.raises(ValueError):
        safe_report_dir("../etc/passwd")


def test_html_escaping(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
    get_settings.cache_clear()
    settings = get_settings()
    settings.reports_dir = tmp_path
    scan_id = str(uuid.uuid4())
    create_report_dir(scan_id)
    vuln = NormalizedVulnerability(
        id="<script>alert(1)</script>",
        severity="High",
        package_name="pkg<script>",
        description="<b>x</b>",
    )
    path = generate_html_report(
        scan_id,
        metadata={"requested_image": "img<script>", "digest": "sha256:abc"},
        counts=SeverityCounts(high=1),
        stats={"fixable": 0, "kev": 0, "unique_cve": 1, "total": 1},
        vulns=[vuln],
        policy_result=PolicyResult(
            status="NON_COMPLIANT",
            policy_name="default",
            policy_hash="abc",
            failures=["fail <script>"],
        ),
    )
    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    get_settings.cache_clear()
