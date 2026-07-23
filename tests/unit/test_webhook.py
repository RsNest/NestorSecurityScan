"""Webhook secret and payload parsing tests."""

import hmac
import inspect

from app.api import webhooks
from app.api.webhooks import parse_push_artifact, verify_webhook_secret


def test_verify_uses_compare_digest():
    src = inspect.getsource(webhooks.verify_webhook_secret)
    assert "hmac.compare_digest" in src
    assert verify_webhook_secret("secret", "secret") is True
    assert verify_webhook_secret("secreT", "secret") is False
    assert verify_webhook_secret(None, "secret") is False
    assert verify_webhook_secret("x", "") is True  # empty expected disables check


def test_parse_push_artifact(monkeypatch):
    monkeypatch.setenv("HARBOR_URL", "https://harbor.example.ru")
    from app.config import get_settings

    get_settings.cache_clear()
    payload = {
        "type": "PUSH_ARTIFACT",
        "occur_at": 123,
        "event_data": {
            "repository": {"namespace": "proj", "name": "app"},
            "resources": [
                {"digest": "sha256:" + "b" * 64, "tag": "1.0"},
            ],
        },
    }
    result = parse_push_artifact(payload)
    assert result is not None
    image, event_id = result
    assert image.startswith("harbor.example.ru/proj/app@sha256:")
    assert event_id is not None
    get_settings.cache_clear()


def test_ignore_other_events(monkeypatch):
    monkeypatch.setenv("HARBOR_URL", "https://harbor.example.ru")
    from app.config import get_settings

    get_settings.cache_clear()
    assert parse_push_artifact({"type": "DELETE_ARTIFACT", "event_data": {}}) is None
    get_settings.cache_clear()
