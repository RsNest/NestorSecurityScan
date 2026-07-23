"""Image reference parsing and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.errors import ImageReferenceError

# Forbid shell metacharacters and path traversal in image refs.
_UNSAFE = re.compile(r"[;&|`$<>\\\n\r\t]|(\.\./)")
_DIGEST_RE = re.compile(r"^sha256:[a-fA-F0-9]{64}$")
_NAME_RE = re.compile(
    r"^(?:(?P<registry>[a-zA-Z0-9][a-zA-Z0-9.-]*(?::[0-9]+)?)/)?"
    r"(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"(?::(?P<tag>[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}))?"
    r"(?:@(?P<digest>sha256:[a-fA-F0-9]{64}))?$"
)

DEFAULT_TAG = "latest"


@dataclass(frozen=True)
class ImageReference:
    raw: str
    registry: str
    repository: str
    tag: str | None
    digest: str | None

    @property
    def reference_for_scan(self) -> str:
        if self.digest:
            return f"{self.registry}/{self.repository}@{self.digest}"
        tag = self.tag or DEFAULT_TAG
        return f"{self.registry}/{self.repository}:{tag}"

    @property
    def display(self) -> str:
        if self.digest and self.tag:
            return f"{self.registry}/{self.repository}:{self.tag}@{self.digest}"
        return self.reference_for_scan

    def with_digest(self, digest: str) -> ImageReference:
        if not _DIGEST_RE.match(digest):
            raise ImageReferenceError(f"Некорректный digest: {digest}")
        return ImageReference(
            raw=self.raw,
            registry=self.registry,
            repository=self.repository,
            tag=self.tag,
            digest=digest,
        )


def parse_image_reference(value: str) -> ImageReference:
    raw = (value or "").strip()
    if not raw:
        raise ImageReferenceError("Укажите имя образа.")
    if len(raw) > 512:
        raise ImageReferenceError("Слишком длинная ссылка на образ.")
    if _UNSAFE.search(raw):
        raise ImageReferenceError("Недопустимые символы в ссылке на образ.")
    if " " in raw:
        raise ImageReferenceError("Пробелы в ссылке на образ недопустимы.")

    match = _NAME_RE.match(raw)
    if not match:
        raise ImageReferenceError(
            "Некорректная ссылка на образ. Ожидается registry/repo:tag или registry/repo@sha256:..."
        )

    registry = match.group("registry")
    repository = match.group("repository")
    tag = match.group("tag")
    digest = match.group("digest")

    if registry is None:
        # docker.io / library short names: alpine:3.20 → docker.io/library/alpine:3.20
        registry = "docker.io"
        if "/" not in repository:
            repository = f"library/{repository}"

    if tag is None and digest is None:
        tag = DEFAULT_TAG

    return ImageReference(
        raw=raw,
        registry=registry,
        repository=repository,
        tag=tag,
        digest=digest,
    )


def registry_host(registry: str) -> str:
    """Host used in Docker config.json auths key."""
    if registry == "docker.io":
        return "https://index.docker.io/v1/"
    return registry.split("/")[0]
