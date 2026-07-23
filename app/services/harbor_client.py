"""Harbor Registry API client."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote

import httpx

from app.config import Settings, get_settings
from app.errors import HarborError

logger = logging.getLogger(__name__)


class HarborClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        if not self.settings.harbor_url:
            raise HarborError("Harbor URL не задан. Укажите HARBOR_URL в .env.")
        self.base = self.settings.harbor_url.rstrip("/")
        self._auth = None
        if self.settings.harbor_username:
            self._auth = (
                self.settings.harbor_username,
                self.settings.harbor_password or "",
            )

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base,
            auth=self._auth,
            verify=self.settings.harbor_verify_tls,
            timeout=30.0,
            headers={"Accept": "application/json"},
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        delays = [0.5, 1.0, 2.0, 4.0]
        last_exc: Exception | None = None
        with self._client() as client:
            for attempt, delay in enumerate([0.0, *delays]):
                if delay:
                    time.sleep(delay)
                try:
                    response = client.request(method, path, **kwargs)
                except httpx.TransportError as exc:
                    last_exc = HarborError(
                        f"Harbor недоступен: {self.base}. Проверьте сеть и URL."
                    )
                    logger.warning("Harbor transport error on %s %s", method, path)
                    continue

                if response.status_code in {429, 500, 502, 503, 504} and attempt < len(delays):
                    logger.warning(
                        "Harbor returned %s, retrying",
                        response.status_code,
                    )
                    continue
                return self._raise_for_status(response)
        raise last_exc or HarborError("Не удалось выполнить запрос к Harbor.")

    def _raise_for_status(self, response: httpx.Response) -> httpx.Response:
        code = response.status_code
        if code == 401:
            raise HarborError(
                "Неверные credentials Harbor (401). Проверьте robot account."
            )
        if code == 403:
            raise HarborError(
                "Недостаточно прав Harbor (403). Нужны list/read/pull для репозиториев."
            )
        if code == 404:
            raise HarborError("Ресурс Harbor не найден (404).")
        if code == 429:
            raise HarborError("Превышен лимит запросов Harbor (429). Повторите позже.")
        if code >= 500:
            raise HarborError(f"Ошибка сервера Harbor ({code}).")
        if code >= 400:
            raise HarborError(f"Ошибка Harbor API ({code}): {response.text[:300]}")
        return response

    def ping(self) -> bool:
        self._request("GET", "/api/v2.0/ping")
        return True

    def list_projects(self, page_size: int = 50) -> list[dict[str, Any]]:
        return self._paginate("/api/v2.0/projects", page_size=page_size)

    def list_repositories(self, project: str, page_size: int = 50) -> list[dict[str, Any]]:
        project_enc = quote(project, safe="")
        return self._paginate(
            f"/api/v2.0/projects/{project_enc}/repositories",
            page_size=page_size,
        )

    def list_artifacts(
        self,
        project: str,
        repository: str,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        # Harbor expects repository name URL-encoded; nested paths use %2F
        # Endpoint uses repository name WITHOUT project prefix in some versions;
        # Harbor v2 uses full name under projects/{project}/repositories/{repo}
        repo_name = repository
        if repository.startswith(f"{project}/"):
            repo_name = repository[len(project) + 1 :]
        project_enc = quote(project, safe="")
        repo_enc = quote(repo_name, safe="")
        return self._paginate(
            f"/api/v2.0/projects/{project_enc}/repositories/{repo_enc}/artifacts",
            page_size=page_size,
            params={"with_tag": "true", "with_scan_overview": "false"},
        )

    def _paginate(
        self,
        path: str,
        *,
        page_size: int = 50,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        page = 1
        items: list[dict[str, Any]] = []
        while True:
            query = dict(params or {})
            query.update({"page": page, "page_size": page_size})
            response = self._request("GET", path, params=query)
            batch = response.json()
            if not isinstance(batch, list):
                break
            items.extend(batch)
            if len(batch) < page_size:
                break
            page += 1
            if page > 1000:
                break
        return items

    def artifact_to_image_ref(
        self,
        project: str,
        repository: str,
        artifact: dict[str, Any],
    ) -> str | None:
        digest = artifact.get("digest")
        if not digest:
            return None
        host = self.base.replace("https://", "").replace("http://", "").split("/")[0]
        repo = repository
        if not repo.startswith(f"{project}/"):
            repo = f"{project}/{repository}" if not repository.startswith(project) else repository
        # repository from Harbor list often includes project name
        if repository.startswith(f"{project}/"):
            full_repo = repository
        else:
            full_repo = f"{project}/{repository}"
        return f"{host}/{full_repo}@{digest}"
