"""Harbor client pagination tests with httpx mock transport."""

import httpx
import pytest

from app.config import Settings
from app.services.harbor_client import HarborClient


class MockTransport(httpx.MockTransport):
    def __init__(self, handler):
        super().__init__(handler)


def test_pagination(monkeypatch):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        calls["n"] += 1
        if page == 1:
            return httpx.Response(200, json=[{"name": "a"}, {"name": "b"}])
        if page == 2:
            return httpx.Response(200, json=[{"name": "c"}])
        return httpx.Response(200, json=[])

    settings = Settings(
        harbor_url="https://harbor.example.ru",
        harbor_username="u",
        harbor_password="p",
        harbor_enabled=True,
    )
    client = HarborClient(settings)

    def _client():
        return httpx.Client(
            base_url=settings.harbor_url,
            transport=httpx.MockTransport(handler),
            auth=("u", "p"),
        )

    client._client = _client  # type: ignore[method-assign]
    items = client.list_projects(page_size=2)
    assert [i["name"] for i in items] == ["a", "b", "c"]
    assert calls["n"] >= 2
