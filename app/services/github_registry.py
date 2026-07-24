"""GitHub Container Registry (ghcr.io) client.

Uses GitHub REST API for listing packages/repos and ghcr.io Docker
Registry HTTP API v2 for tag/digest resolution. Auth via PAT with
read:packages scope.
"""

from __future__ import annotations

import base64
import logging
from typing import Any
from urllib.parse import quote

import httpx

from app.config import Settings, get_settings
from app.errors import RegistryError

logger = logging.getLogger(__name__)

GH_API = "https://api.github.com"
GHCR_REGISTRY = "https://ghcr.io"


class GitHubRegistryError(RegistryError):
    pass


class GitHubRegistryClient:
    def __init__(self, settings: Settings | None = None):
        s = settings or get_settings()
        if not s.github_token:
            raise GitHubRegistryError(
                "GITHUB_TOKEN не задан. Укажите PAT с правами read:packages в .env."
            )
        self.token = s.github_token
        self._auth_header = "Basic " + base64.b64encode(
            f"x-access-token:{s.github_token}".encode()
        ).decode("utf-8")

    def _gh(self) -> httpx.Client:
        return httpx.Client(
            base_url=GH_API,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    def _registry(self) -> httpx.Client:
        return httpx.Client(
            base_url=GHCR_REGISTRY,
            headers={
                "Authorization": self._auth_header,
                "Accept": "application/vnd.docker.distribution.manifest.v2+json,"
                "application/vnd.oci.image.manifest.v1+json,"
                "application/vnd.docker.distribution.manifest.list.v2+json,"
                "application/vnd.oci.image.index.v1+json",
            },
            timeout=30.0,
        )

    def ping(self) -> bool:
        with self._gh() as c:
            r = c.get("/user")
            if r.status_code == 401:
                raise GitHubRegistryError("Неверный GitHub token (401).")
            if r.status_code >= 400:
                raise GitHubRegistryError(f"GitHub API: {r.status_code}")
            user = r.json().get("login", "?")
            logger.info("GitHub auth OK as %s", user)
        return True

    def list_container_repositories(
        self, owner: str | None = None, page_size: int = 50
    ) -> list[dict[str, Any]]:
        with self._gh() as c:
            items: list[dict[str, Any]] = []
            page = 1
            while True:
                path = f"/orgs/{owner}/packages" if owner else "/user/packages"
                r = c.get(
                    path,
                    params={"package_type": "container", "per_page": page_size, "page": page},
                )
                if r.status_code == 404 and owner:
                    # fallback to user-packages
                    r = c.get(
                        "/user/packages",
                        params={
                            "package_type": "container",
                            "per_page": page_size,
                            "page": page,
                        },
                    )
                if r.status_code >= 400:
                    raise GitHubRegistryError(
                        f"GitHub list packages: {r.status_code} {r.text[:200]}"
                    )
                batch = r.json() or []
                items.extend(batch)
                if len(batch) < page_size:
                    break
                page += 1
                if page > 200:
                    break
        return items

    def list_tags(self, owner: str, package: str, page_size: int = 50) -> list[dict[str, Any]]:
        with self._gh() as c:
            items: list[dict[str, Any]] = []
            page = 1
            while True:
                r = c.get(
                    f"/user/packages/container/{quote(owner)}/{quote(package)}/versions",
                    params={"per_page": page_size, "page": page},
                )
                if r.status_code >= 400:
                    raise GitHubRegistryError(
                        f"GitHub list versions: {r.status_code} {r.text[:200]}"
                    )
                batch = r.json() or []
                items.extend(batch)
                if len(batch) < page_size:
                    break
                page += 1
                if page > 200:
                    break
        return items

    def tag_to_digest(self, owner: str, package: str, tag: str) -> str | None:
        with self._registry() as c:
            r = c.get(f"/v2/{owner}/{package}/manifests/{tag}")
            if r.status_code == 404:
                return None
            if r.status_code >= 400:
                raise GitHubRegistryError(
                    f"ghcr.io manifest: {r.status_code} {r.text[:200]}"
                )
            digest = r.headers.get("Docker-Content-Digest")
            return digest

    def artifact_to_image_ref(
        self, owner: str, package: str, version: dict[str, Any]
    ) -> str | None:
        digest = None
        for img in version.get("package_version_manifests", []) or []:
            digest = img.get("digest") or digest
        name = version.get("name") or version.get("tag")
        if not digest:
            digest = self.tag_to_digest(owner, package, name or "latest")
        if not digest:
            return None
        return f"ghcr.io/{owner}/{package}@{digest}"

    def list_artifacts(
        self, owner: str, package: str
    ) -> list[str]:
        versions = self.list_tags(owner, package)
        out: list[str] = []
        for v in versions:
            ref = self.artifact_to_image_ref(owner, package, v)
            if ref:
                out.append(ref)
        return out
