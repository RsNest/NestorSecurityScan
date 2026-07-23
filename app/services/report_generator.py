"""Report directory management and HTML/JSON report generation."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.schemas import NormalizedVulnerability, PolicyResult, SeverityCounts

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)


def safe_report_dir(scan_id: str) -> Path:
    if not _UUID_RE.match(scan_id):
        raise ValueError("Некорректный scan_id")
    settings = get_settings()
    path = (settings.reports_dir / scan_id).resolve()
    reports_root = settings.reports_dir.resolve()
    if not str(path).startswith(str(reports_root)):
        raise ValueError("Path traversal detected")
    return path


def create_report_dir(scan_id: str) -> Path:
    path = safe_report_dir(scan_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def append_scan_log(scan_id: str, message: str) -> None:
    path = safe_report_dir(scan_id) / "scan.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"[{ts}] {message}\n")


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def write_metadata(scan_id: str, metadata: dict[str, Any]) -> None:
    # Never persist secrets
    forbidden = {"password", "token", "secret", "authorization", "auth", "api_key"}
    cleaned = {
        k: v
        for k, v in metadata.items()
        if not any(f in k.lower() for f in forbidden)
    }
    write_json(safe_report_dir(scan_id) / "metadata.json", cleaned)


def write_normalized_report(
    scan_id: str,
    *,
    metadata: dict[str, Any],
    counts: SeverityCounts,
    stats: dict[str, int],
    vulns: list[NormalizedVulnerability],
    policy_result: PolicyResult,
    warnings: list[str] | None = None,
) -> Path:
    payload = {
        "metadata": metadata,
        "summary": {
            "counts": counts.model_dump(),
            "stats": stats,
            "policy": policy_result.model_dump(),
        },
        "vulnerabilities": [v.model_dump() for v in vulns],
        "warnings": warnings or [],
    }
    path = safe_report_dir(scan_id) / "normalized-report.json"
    write_json(path, payload)
    return path


def generate_html_report(
    scan_id: str,
    *,
    metadata: dict[str, Any],
    counts: SeverityCounts,
    stats: dict[str, int],
    vulns: list[NormalizedVulnerability],
    policy_result: PolicyResult,
    warnings: list[str] | None = None,
) -> Path:
    path = safe_report_dir(scan_id) / "report.html"
    rows = []
    for v in vulns:
        urls = " ".join(
            f'<a href="{html.escape(u, quote=True)}" target="_blank" rel="noopener">'
            f"{html.escape(u)}</a>"
            for u in (v.urls or [])[:3]
        )
        rows.append(
            "<tr"
            f' data-severity="{html.escape(v.severity.lower())}"'
            f' data-package="{html.escape((v.package_name or "").lower())}"'
            f' data-fix="{"yes" if v.fixed_version else "no"}"'
            f' data-kev="{"yes" if v.kev else "no"}"'
            f' data-ignored="{"yes" if v.ignored else "no"}">'
            f"<td>{html.escape(v.id)}</td>"
            f"<td>{html.escape(v.severity)}</td>"
            f"<td>{html.escape(v.package_name or '')}</td>"
            f"<td>{html.escape(v.installed_version or '')}</td>"
            f"<td>{html.escape(v.fixed_version or '')}</td>"
            f"<td>{html.escape('' if v.epss is None else f'{v.epss:.4f}')}</td>"
            f"<td>{'KEV' if v.kev else ''}</td>"
            f"<td>{html.escape(v.ignore_reason or '')}</td>"
            f"<td>{html.escape(v.ignore_expires_at or '')}</td>"
            f"<td>{urls}</td>"
            "</tr>"
        )

    warning_html = "".join(f"<li>{html.escape(w)}</li>" for w in (warnings or []))
    failures_html = "".join(f"<li>{html.escape(f)}</li>" for f in policy_result.failures)

    content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Nestor Security Scanner — отчёт {html.escape(scan_id)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 1.5rem; color: #1a1a1a; background: #f7f7f5; }}
h1,h2 {{ margin-bottom: .4rem; }}
.meta,.summary {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); gap: .75rem; margin: 1rem 0; }}
.card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: .75rem 1rem; }}
.status-COMPLIANT {{ color: #0a7a34; font-weight: 700; }}
.status-NON_COMPLIANT {{ color: #b00020; font-weight: 700; }}
.status-COMPLIANT_WITH_EXCEPTIONS {{ color: #9a6700; font-weight: 700; }}
.filters {{ display: flex; flex-wrap: wrap; gap: .5rem; margin: 1rem 0; align-items: end; }}
.filters label {{ display: flex; flex-direction: column; font-size: .85rem; gap: .25rem; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; }}
th,td {{ border: 1px solid #ddd; padding: .45rem .55rem; font-size: .9rem; vertical-align: top; }}
th {{ background: #eee; text-align: left; position: sticky; top: 0; }}
.hidden {{ display: none; }}
</style>
</head>
<body>
<h1>Nestor Security Scanner — отчёт сканирования</h1>
<p>Scan ID: <code>{html.escape(scan_id)}</code></p>
<div class="meta">
  <div class="card"><div>Образ</div><strong>{html.escape(str(metadata.get("requested_image") or ""))}</strong></div>
  <div class="card"><div>Canonical</div><strong>{html.escape(str(metadata.get("canonical_image") or ""))}</strong></div>
  <div class="card"><div>Digest</div><strong>{html.escape(str(metadata.get("digest") or ""))}</strong></div>
  <div class="card"><div>Дата</div><strong>{html.escape(str(metadata.get("finished_at") or metadata.get("created_at") or ""))}</strong></div>
  <div class="card"><div>Статус</div><strong class="status-{html.escape(policy_result.status)}">{html.escape(policy_result.status)}</strong></div>
  <div class="card"><div>Политика</div><strong>{html.escape(policy_result.policy_name)}</strong></div>
  <div class="card"><div>Syft</div><strong>{html.escape(str(metadata.get("syft_version") or ""))}</strong></div>
  <div class="card"><div>Grype</div><strong>{html.escape(str(metadata.get("grype_version") or ""))}</strong></div>
  <div class="card"><div>Grype DB</div><strong>{html.escape(str(metadata.get("grype_database_built_at") or ""))}</strong></div>
</div>
<div class="summary">
  <div class="card">Critical: <strong>{counts.critical}</strong></div>
  <div class="card">High: <strong>{counts.high}</strong></div>
  <div class="card">Medium: <strong>{counts.medium}</strong></div>
  <div class="card">Low: <strong>{counts.low}</strong></div>
  <div class="card">Исправимые: <strong>{stats.get("fixable", 0)}</strong></div>
  <div class="card">KEV: <strong>{stats.get("kev", 0)}</strong></div>
  <div class="card">Уникальные CVE: <strong>{stats.get("unique_cve", 0)}</strong></div>
</div>
<h2>Нарушения политики</h2>
<ul>{failures_html or "<li>Нет</li>"}</ul>
<h2>Предупреждения</h2>
<ul>{warning_html or "<li>Нет</li>"}</ul>
<h2>Уязвимости</h2>
<div class="filters">
  <label>Severity
    <select id="fSeverity">
      <option value="">Все</option>
      <option>critical</option><option>high</option><option>medium</option>
      <option>low</option><option>negligible</option><option>unknown</option>
    </select>
  </label>
  <label>Package <input id="fPackage" placeholder="имя пакета"/></label>
  <label>Fix
    <select id="fFix"><option value="">Все</option><option value="yes">Есть fix</option><option value="no">Нет fix</option></select>
  </label>
  <label>KEV
    <select id="fKev"><option value="">Все</option><option value="yes">KEV</option><option value="no">Не KEV</option></select>
  </label>
  <label>Ignored
    <select id="fIgnored"><option value="">Все</option><option value="yes">Ignored</option><option value="no">Not ignored</option></select>
  </label>
</div>
<table>
<thead><tr>
<th>CVE</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed</th>
<th>EPSS</th><th>KEV</th><th>Ignore reason</th><th>Expires</th><th>Links</th>
</tr></thead>
<tbody id="vulnBody">
{''.join(rows)}
</tbody>
</table>
<script>
(function() {{
  const body = document.getElementById('vulnBody');
  const rows = Array.from(body.querySelectorAll('tr'));
  function apply() {{
    const sev = document.getElementById('fSeverity').value.toLowerCase();
    const pkg = document.getElementById('fPackage').value.toLowerCase();
    const fix = document.getElementById('fFix').value;
    const kev = document.getElementById('fKev').value;
    const ign = document.getElementById('fIgnored').value;
    rows.forEach(r => {{
      const ok =
        (!sev || r.dataset.severity === sev) &&
        (!pkg || (r.dataset.package || '').includes(pkg)) &&
        (!fix || r.dataset.fix === fix) &&
        (!kev || r.dataset.kev === kev) &&
        (!ign || r.dataset.ignored === ign);
      r.classList.toggle('hidden', !ok);
    }});
  }}
  ['fSeverity','fPackage','fFix','fKev','fIgnored'].forEach(id => {{
    document.getElementById(id).addEventListener('input', apply);
    document.getElementById(id).addEventListener('change', apply);
  }});
}})();
</script>
</body>
</html>
"""
    path.write_text(content, encoding="utf-8")
    return path


def delete_report_dir(scan_id: str) -> None:
    import shutil

    path = safe_report_dir(scan_id)
    if path.exists():
        shutil.rmtree(path)
