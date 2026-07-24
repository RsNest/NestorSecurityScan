"""SQLAlchemy ORM models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_scan_id() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (UniqueConstraint("webhook_event_id", name="uq_webhook_event_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_scan_id)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    requested_image: Mapped[str] = mapped_column(String(512), nullable=False)
    canonical_image: Mapped[str | None] = mapped_column(String(512), nullable=True)
    registry: Mapped[str | None] = mapped_column(String(255), nullable=True)
    repository: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tag: Mapped[str | None] = mapped_column(String(255), nullable=True)
    digest: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    status: Mapped[str] = mapped_column(String(64), nullable=False, default="QUEUED", index=True)
    stage: Mapped[str] = mapped_column(String(64), nullable=False, default="QUEUED")
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    negligible_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_vulns: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_cve_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fixable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unfixable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kev_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_epss_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    policy_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rq_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    webhook_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    syft_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    grype_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    grype_db_built_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os: Mapped[str | None] = mapped_column(String(64), nullable=True)

    cancel_requested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AppState(Base):
    """Key-value store for global status (Grype DB, etc.)."""

    __tablename__ = "app_state"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class User(Base):
    """Local user with bcrypt-hashed password and role for RBAC."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer")
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


ACTIVE_SCAN_STATUSES = (
    "QUEUED",
    "RESOLVING_IMAGE",
    "GENERATING_SBOM",
    "SCANNING",
    "APPLYING_POLICY",
    "GENERATING_REPORT",
    "RUNNING",
)

TERMINAL_STATUSES = (
    "COMPLIANT",
    "NON_COMPLIANT",
    "COMPLIANT_WITH_EXCEPTIONS",
    "ERROR",
    "CANCELLED",
)
