"""Application configuration from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Nestor Security Scanner"
    app_env: str = "development"
    web_port: int = 8080
    log_level: str = "INFO"
    service_name: str = "api"

    data_dir: Path = Path("/data")
    reports_dir: Path = Path("/data/reports")
    database_url: str = "sqlite:////data/scanner.db"

    redis_url: str = "redis://redis:6379/0"
    max_concurrent_scans: int = 2
    scan_timeout_minutes: int = 30

    policy_file: Path = Path("/policies/default.yaml")
    api_key: str = ""
    session_secret: str = "change-me-in-prod-please-32-chars-minimum"
    session_max_age_seconds: int = 60 * 60 * 12

    admin_user: str = ""
    admin_password: str = ""

    rescan_after_db_update: bool = True
    rescan_recent_days: int = 30

    github_token: str = ""
    github_registry_enabled: bool = False

    harbor_enabled: bool = False
    harbor_url: str = ""
    harbor_username: str = ""
    harbor_password: str = ""
    harbor_verify_tls: bool = True
    harbor_projects: str = ""
    harbor_webhook_secret: str = ""

    discovery_enabled: bool = False
    discovery_interval_minutes: int = 60

    grype_db_cache_dir: Path = Path("/data/grype-db")
    grype_db_auto_update: bool = True
    grype_db_update_interval_hours: int = 24

    report_retention_days: int = 30

    syft_bin: str = "syft"
    grype_bin: str = "grype"
    auth_tmp_dir: Path = Path("/tmp/scanner-auth")
    certs_dir: Path = Path("/certs")

    webhook_max_body_bytes: int = Field(default=1_048_576, ge=1024)

    @property
    def harbor_project_filters(self) -> list[str]:
        if not self.harbor_projects.strip():
            return []
        return [p.strip() for p in self.harbor_projects.split(",") if p.strip()]

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.grype_db_cache_dir.mkdir(parents=True, exist_ok=True)
        self.auth_tmp_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
