"""Runtime configuration with safe defaults."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# RFC 7518 section 3.2: an HMAC key must be at least as long as the hash output.
MINIMUM_HMAC_KEY_BYTES = 32


class Settings(BaseSettings):
    """Gateway settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="GUARDRAIL_", extra="ignore")

    policy_version: str = "2026-08-29.1"
    approval_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    max_content_chars: int = Field(default=20_000, ge=100, le=1_000_000)
    audit_buffer_size: int = Field(default=1_000, ge=10, le=100_000)

    # Signing material for caller credentials. There is deliberately no
    # "authentication disabled" switch: when this is unset the gateway cannot
    # prove who is calling, so it refuses every enforcement request instead of
    # trusting an identity asserted in a request body.
    jwt_secret: SecretStr | None = None
    jwt_algorithm: Literal["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"] = "HS256"
    jwt_issuer: str | None = None
    jwt_audience: str | None = None

    @model_validator(mode="after")
    def _reject_weak_hmac_key(self) -> Self:
        """Refuse a shared secret short enough to attack offline.

        A deployment that supplies a weak key would otherwise look protected
        while every credential in the system is forgeable, so this is a
        configuration error rather than a warning.
        """

        if self.jwt_secret is None or not self.jwt_algorithm.startswith("HS"):
            return self
        if len(self.jwt_secret.get_secret_value().encode()) < MINIMUM_HMAC_KEY_BYTES:
            raise ValueError(
                f"jwt_secret must be at least {MINIMUM_HMAC_KEY_BYTES} bytes "
                f"for {self.jwt_algorithm}"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings object."""

    return Settings()
