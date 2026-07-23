"""YAML policy engine for vulnerability compliance."""

from __future__ import annotations

import hashlib
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from app.errors import PolicyError
from app.schemas import NormalizedVulnerability, PolicyResult, SeverityCounts


class IgnoreRule(BaseModel):
    vulnerability: str
    package: str | None = None
    reason: str = ""
    approved_by: str | None = None
    expires_at: date | None = None


class FailRules(BaseModel):
    severities: list[str] = Field(default_factory=lambda: ["critical", "high"])
    only_fixed: bool = False


class KevRules(BaseModel):
    fail_if_present: bool = False


class EpssRules(BaseModel):
    enabled: bool = False
    minimum_probability: float = 0.70


class PolicyDocument(BaseModel):
    version: int = 1
    name: str = "default"
    fail: FailRules = Field(default_factory=FailRules)
    thresholds: dict[str, int] = Field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 20}
    )
    kev: KevRules = Field(default_factory=KevRules)
    epss: EpssRules = Field(default_factory=EpssRules)
    ignore: list[IgnoreRule] = Field(default_factory=list)


def policy_hash(content: bytes | str) -> str:
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()


def load_policy(path: Path) -> tuple[PolicyDocument, str]:
    if not path.exists():
        raise PolicyError(f"Файл политики не найден: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        policy = PolicyDocument.model_validate(data)
        return policy, policy_hash(raw)
    except PolicyError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PolicyError(f"Policy YAML некорректен: {exc}") from exc


def _rule_active(rule: IgnoreRule, today: date) -> bool:
    if rule.expires_at is None:
        return True
    return rule.expires_at >= today


def _matches_ignore(vuln: NormalizedVulnerability, rule: IgnoreRule) -> bool:
    if vuln.id.lower() != rule.vulnerability.lower():
        return False
    if rule.package:
        if not vuln.package_name or vuln.package_name.lower() != rule.package.lower():
            return False
    return True


def apply_policy(
    vulns: list[NormalizedVulnerability],
    counts: SeverityCounts,
    policy: PolicyDocument,
    policy_sha: str,
    *,
    today: date | None = None,
) -> tuple[list[NormalizedVulnerability], PolicyResult]:
    today = today or date.today()
    applied: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    annotated: list[NormalizedVulnerability] = []

    for vuln in vulns:
        ignored = False
        reason = None
        expires = None
        approved = None
        for rule in policy.ignore:
            if not _matches_ignore(vuln, rule):
                continue
            info = {
                "vulnerability": rule.vulnerability,
                "package": rule.package,
                "reason": rule.reason,
                "approved_by": rule.approved_by,
                "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
            }
            if _rule_active(rule, today):
                ignored = True
                reason = rule.reason
                expires = info["expires_at"]
                approved = rule.approved_by
                applied.append(info)
                break
            expired.append(info)

        annotated.append(
            vuln.model_copy(
                update={
                    "ignored": ignored,
                    "ignore_reason": reason,
                    "ignore_expires_at": expires,
                    "ignore_approved_by": approved,
                }
            )
        )

    active = [v for v in annotated if not v.ignored]
    failures: list[str] = []

    # Recount severities for active (non-ignored) vulns
    active_counts = SeverityCounts()
    for v in active:
        key = v.severity.lower()
        if hasattr(active_counts, key):
            setattr(active_counts, key, getattr(active_counts, key) + 1)
        else:
            active_counts.unknown += 1

    fail_severities = {s.lower() for s in policy.fail.severities}
    for sev in fail_severities:
        n = getattr(active_counts, sev, 0)
        if n > 0:
            if policy.fail.only_fixed:
                fixed_n = sum(
                    1
                    for v in active
                    if v.severity.lower() == sev and v.fixed_version
                )
                if fixed_n > 0:
                    failures.append(
                        f"Найдены исправимые уязвимости severity={sev}: {fixed_n}"
                    )
            else:
                failures.append(f"Найдены уязвимости severity={sev}: {n}")

    for sev, limit in policy.thresholds.items():
        n = getattr(active_counts, sev.lower(), 0)
        if n > limit:
            failures.append(f"Превышен порог {sev}: {n} > {limit}")

    if policy.kev.fail_if_present:
        kev_n = sum(1 for v in active if v.kev)
        if kev_n:
            failures.append(f"Найдены KEV-уязвимости: {kev_n}")

    if policy.epss.enabled:
        epss_n = sum(
            1
            for v in active
            if v.epss is not None and v.epss >= policy.epss.minimum_probability
        )
        if epss_n:
            failures.append(
                f"Найдены CVE с EPSS >= {policy.epss.minimum_probability}: {epss_n}"
            )

    if failures:
        status = "NON_COMPLIANT"
    elif applied:
        status = "COMPLIANT_WITH_EXCEPTIONS"
    else:
        status = "COMPLIANT"

    result = PolicyResult(
        status=status,
        policy_name=policy.name,
        policy_hash=policy_sha,
        failures=failures,
        applied_exceptions=applied,
        expired_exceptions=expired,
    )
    return annotated, result
