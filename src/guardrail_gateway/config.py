"""Runtime configuration with safe defaults."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Gateway settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="GUARDRAIL_", extra="ignore")

    policy_version: str = "2026-08-29.1"
    approval_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    max_content_chars: int = Field(default=20_000, ge=100, le=1_000_000)
    audit_buffer_size: int = Field(default=1_000, ge=10, le=100_000)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings object."""

    return Settings()
