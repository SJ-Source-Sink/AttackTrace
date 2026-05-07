"""
Application configuration using Pydantic Settings.
All settings can be overridden via environment variables.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "AttackTrace"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # API
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "change-me-in-production-use-32-char-min"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://attacktrace:attacktrace@localhost:5432/attacktrace"
    # Set DATABASE_READ_REPLICA_URL to a read replica DSN to split read traffic.
    # Defaults to the primary so no infra change is required right now.
    DATABASE_READ_REPLICA_URL: Optional[str] = None
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_STATEMENT_TIMEOUT_MS: int = 30000  # 30s per query

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_SCAN_PUBSUB_DB: int = 1

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    CORS_ALLOW_CREDENTIALS: bool = True

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/2"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/3"
    CELERY_TASK_SOFT_TIME_LIMIT: int = 7200  # 2 hours
    CELERY_TASK_TIME_LIMIT: int = 7800  # 2h 10m

    # Encryption
    KMS_MASTER_KEY: str = "change-me-32-bytes-base64-encoded=="

    # Anthropic AI
    ANTHROPIC_API_KEY: Optional[str] = None
    AI_MODEL: str = "claude-haiku-4-5-20251001"
    AI_MAX_TOKENS: int = 2048

    # AttackTrace CLI
    ATTACKTRACE_WORKSPACE_DIR: str = str(Path.home() / ".attacktrace" / "scans")

    # MSRA — Mobile Security Review Assistant sidecar
    MSRA_URL: str = "http://localhost:5001"

    # Pagination defaults
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 200

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    @field_validator("SECRET_KEY", mode="after")
    @classmethod
    def validate_secret_key_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                import json
                return json.loads(v)
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


    def validate_production_secrets(self) -> None:
        """Fail fast if insecure defaults are used outside development."""
        if self.ENVIRONMENT != "development":
            insecure_defaults = [
                "change-me-in-production-use-32-char-min",
                "change-me-32-bytes-base64-encoded==",
            ]
            if self.SECRET_KEY in insecure_defaults:
                raise RuntimeError(
                    "SECRET_KEY must be changed from the default value in non-development environments."
                )
            if self.KMS_MASTER_KEY in insecure_defaults:
                raise RuntimeError(
                    "KMS_MASTER_KEY must be changed from the default value in non-development environments."
                )


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.validate_production_secrets()
    return s
