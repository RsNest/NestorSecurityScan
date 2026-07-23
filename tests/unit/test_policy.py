"""Policy engine unit tests."""

from datetime import date
from pathlib import Path

from app.schemas import NormalizedVulnerability, SeverityCounts
from app.services.policy_engine import (
    FailRules,
    IgnoreRule,
    PolicyDocument,
    apply_policy,
    load_policy,
)


def _vuln(**kwargs):
    data = {
        "id": "CVE-2025-1",
        "severity": "Critical",
        "package_name": "openssl",
        "installed_version": "1.0",
        "fixed_version": "1.1",
    }
    data.update(kwargs)
    return NormalizedVulnerability(**data)


def test_load_default_policy():
    path = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"
    policy, digest = load_policy(path)
    assert policy.name == "default"
    assert len(digest) == 64


def test_ignore_expired():
    policy = PolicyDocument(
        name="t",
        ignore=[
            IgnoreRule(
                vulnerability="CVE-2025-1",
                package="openssl",
                reason="temp",
                expires_at=date(2020, 1, 1),
            )
        ],
    )
    vulns, result = apply_policy(
        [_vuln()],
        SeverityCounts(critical=1),
        policy,
        "abc",
        today=date(2026, 1, 1),
    )
    assert result.status == "NON_COMPLIANT"
    assert vulns[0].ignored is False
    assert result.expired_exceptions


def test_ignore_active():
    policy = PolicyDocument(
        name="t",
        ignore=[
            IgnoreRule(
                vulnerability="CVE-2025-1",
                package="openssl",
                reason="ok",
                expires_at=date(2099, 1, 1),
            )
        ],
    )
    vulns, result = apply_policy(
        [_vuln()],
        SeverityCounts(critical=1),
        policy,
        "abc",
        today=date(2026, 1, 1),
    )
    assert result.status == "COMPLIANT_WITH_EXCEPTIONS"
    assert vulns[0].ignored is True


def test_compliant_clean():
    policy = PolicyDocument(
        name="t",
        fail=FailRules(severities=[]),
        thresholds={},
        kev=__import__("app.services.policy_engine", fromlist=["KevRules"]).KevRules(
            fail_if_present=False
        ),
    )
    _, result = apply_policy([], SeverityCounts(), policy, "abc")
    assert result.status == "COMPLIANT"
