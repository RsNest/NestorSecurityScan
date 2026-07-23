"""Pydantic schemas for API and internal DTOs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ScanCreate(BaseModel):
    image: str = Field(..., min_length=1, max_length=512)
    source: str = "manual"
    registry_username: str | None = None
    registry_password: str | None = None
    verify_tls: bool = True
    platform: str | None = None
    policy_file: str | None = None
    webhook_event_id: str | None = None

    @field_validator("image")
    @classmethod
    def strip_image(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("image reference is required")
        return value


class HarborScanRequest(BaseModel):
    images: list[str] = Field(..., min_length=1)
    platform: str | None = None


class ScanSummary(BaseModel):
    id: str
    source: str
    requested_image: str
    canonical_image: str | None = None
    registry: str | None = None
    repository: str | None = None
    tag: str | None = None
    digest: str | None = None
    status: str
    stage: str
    progress: int
    message: str | None = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_vulns: int = 0
    unique_cve_count: int = 0
    fixable_count: int = 0
    kev_count: int = 0
    policy_name: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None
    syft_version: str | None = None
    grype_version: str | None = None
    grype_db_built_at: str | None = None
    duration_seconds: float | None = None

    model_config = {"from_attributes": True}


class HealthResponse(BaseModel):
    status: str
    service: str
    redis: str
    database: str
    grype_db: str = "unknown"
    version: str


class VersionResponse(BaseModel):
    app_version: str
    syft_version: str | None = None
    grype_version: str | None = None


class GrypeDbStatus(BaseModel):
    built_at: str | None = None
    schema_version: str | None = None
    last_check_at: str | None = None
    last_update_at: str | None = None
    last_update_status: str | None = None
    last_error: str | None = None
    stale: bool = False
    ready: bool = False
    bootstrapping: bool = False


class HarborStatus(BaseModel):
    enabled: bool
    configured: bool
    reachable: bool | None = None
    url: str | None = None
    message: str | None = None


class NormalizedVulnerability(BaseModel):
    id: str
    severity: str
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    package_type: str | None = None
    package_path: str | None = None
    data_source: str | None = None
    namespace: str | None = None
    description: str | None = None
    urls: list[str] = Field(default_factory=list)
    epss: float | None = None
    kev: bool = False
    risk_score: float | None = None
    ignored: bool = False
    ignore_reason: str | None = None
    ignore_expires_at: str | None = None
    ignore_approved_by: str | None = None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0


class PolicyResult(BaseModel):
    status: str
    policy_name: str
    policy_hash: str
    failures: list[str] = Field(default_factory=list)
    applied_exceptions: list[dict[str, Any]] = Field(default_factory=list)
    expired_exceptions: list[dict[str, Any]] = Field(default_factory=list)
