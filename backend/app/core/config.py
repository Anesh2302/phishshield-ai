"""Central application configuration.

All settings are read from environment variables (optionally via a .env file).
Nothing secret is ever hard-coded: missing values fall back to explicit
non-secret development defaults and the affected feature is marked disabled.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core ---
    environment: str = "development"
    log_level: str = "INFO"
    secret_key: str = "dev-insecure-secret-key-change-me"
    token_encryption_key: str = ""

    # --- Database ---
    database_url: str = "sqlite+pysqlite:///./phishshield.db"
    postgres_user: str = "phishshield"
    postgres_password: str = "phishshield"
    postgres_db: str = "phishshield"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # --- Web ---
    session_cookie_name: str = "phishshield_session"
    session_ttl_minutes: int = 720
    cors_origins: str = "http://localhost:3000"
    cookie_secure: bool = False

    # --- Rate limiting ---
    rate_limit_per_minute: int = 120
    login_rate_limit_per_minute: int = 10

    # --- Google ---
    google_client_id: str = ""
    google_client_secret: str = ""
    google_oauth_redirect_uri: str = "http://localhost:8000/api/v1/integrations/gmail/callback"
    google_pubsub_topic: str = ""
    google_pubsub_verification_token: str = ""
    gmail_enabled: bool = False

    # --- Microsoft ---
    ms_client_id: str = ""
    ms_client_secret: str = ""
    ms_tenant_id: str = "common"
    ms_oauth_redirect_uri: str = "http://localhost:8000/api/v1/integrations/outlook/callback"
    ms_webhook_client_state: str = ""
    outlook_enabled: bool = False
    public_webhook_base_url: str = ""

    # --- Threat intel ---
    threatintel_enabled: bool = False
    virustotal_api_key: str = ""
    urlhaus_enabled: bool = False
    phishtank_enabled: bool = False

    # --- File analysis ---
    max_upload_mb: int = 25
    upload_dir: str = "./storage/uploads"
    quarantine_dir: str = "./storage/quarantine"
    evidence_dir: str = "./storage/evidence"
    file_reputation_enabled: bool = False
    max_archive_files: int = 500
    max_archive_expansion_ratio: int = 100
    max_extract_bytes: int = 50 * 1024 * 1024

    # --- ML ---
    ml_model_path: str = str(Path(__file__).resolve().parents[3] / "ml" / "artifacts" / "url_model.joblib")
    ml_enabled: bool = True

    # --- Mock providers ---
    mock_providers: bool = False

    @field_validator("cors_origins")
    @classmethod
    def _strip_origins(cls, v: str) -> str:
        return v.strip()

    @property
    def cors_origin_list(self) -> list[str]:
        if not self.cors_origins or self.cors_origins == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def resolved_database_url(self) -> str:
        """Return the effective database URL.

        When DATABASE_URL is left at the SQLite default but PostgreSQL
        connection details look explicitly configured we still honour
        DATABASE_URL, matching twelve-factor expectations.
        """
        return self.database_url

    @property
    def upload_path(self) -> Path:
        p = Path(self.upload_dir)
        return p if p.is_absolute() else (BACKEND_DIR / p).resolve()

    @property
    def quarantine_path(self) -> Path:
        p = Path(self.quarantine_dir)
        return p if p.is_absolute() else (BACKEND_DIR / p).resolve()

    @property
    def evidence_path(self) -> Path:
        p = Path(self.evidence_dir)
        return p if p.is_absolute() else (BACKEND_DIR / p).resolve()

    def capability_report(self) -> dict[str, object]:
        """Boolean capability flags used by /health and /status endpoints."""
        return {
            "database": "postgresql" if self.database_url.startswith("postgresql") else "sqlite",
            "gmail": self.gmail_enabled and bool(self.google_client_id and self.google_client_secret),
            "outlook": self.outlook_enabled and bool(self.ms_client_id and self.ms_client_secret),
            "threat_intel": self.threatintel_enabled or self.urlhaus_enabled or self.phishtank_enabled,
            "file_reputation": self.file_reputation_enabled,
            "ml": self.ml_enabled,
            "mock_providers": self.mock_providers,
            "token_encryption": bool(self.token_encryption_key),
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
