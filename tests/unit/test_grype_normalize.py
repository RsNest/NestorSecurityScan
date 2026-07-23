"""Grype JSON normalization tests."""

from app.services.grype_runner import normalize_grype_json


def test_normalize_grype_fixture():
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1",
                    "severity": "High",
                    "description": "test",
                    "urls": ["https://example.com"],
                    "dataSource": "https://nvd.nist.gov",
                    "fix": {"versions": ["1.2.3"]},
                    "epss": [{"epss": 0.8}],
                    "kev": True,
                },
                "artifact": {
                    "name": "curl",
                    "version": "1.0",
                    "type": "apk",
                    "locations": [{"path": "/usr/bin/curl"}],
                },
            }
        ]
    }
    vulns, counts, stats = normalize_grype_json(data)
    assert len(vulns) == 1
    assert counts.high == 1
    assert stats["fixable"] == 1
    assert stats["kev"] == 1
    assert vulns[0].epss == 0.8
    assert vulns[0].kev is True
