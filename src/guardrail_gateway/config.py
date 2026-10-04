"""Runtime configuration with safe defaults."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from guardrail_gateway.models import EntityAction

# RFC 7518 section 3.2: an HMAC key must be at least as long as the hash output.
MINIMUM_HMAC_KEY_BYTES = 32
MINIMUM_CANARY_CHARS = 12


class Settings(BaseSettings):
    """Gateway settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="GUARDRAIL_", extra="ignore")

    policy_version: str = "2026-08-29.1"
    approval_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    max_content_chars: int = Field(default=20_000, ge=100, le=1_000_000)
    # Section 8.2. The most retrieved text one batch may place before the model.
    max_context_chars: int = Field(default=60_000, ge=100, le=10_000_000)
    audit_buffer_size: int = Field(default=1_000, ge=10, le=100_000)
    # Sections 3 and 13. How many recent decisions and incident cases are kept
    # for the reviewer and the auditor to read.
    decision_log_size: int = Field(default=10_000, ge=10, le=1_000_000)
    incident_store_size: int = Field(default=5_000, ge=10, le=1_000_000)

    # Section 14. Publish audit events to Kafka when set; otherwise they stay
    # in process. Client settings such as TLS and SASL are passed through.
    kafka_bootstrap_servers: str | None = Field(default=None, min_length=1)
    kafka_topic: str = Field(default="guardrail.security-events", pattern=r"^[A-Za-z0-9._-]+$")
    kafka_client_config: dict[str, str | int | bool] = Field(default_factory=dict)
    # Section 11. Offer sandboxed code execution when an image is named. Each
    # run is a new container with no network, no host filesystem, and these
    # limits. The runtime is the container CLI; the OCI runtime, when set,
    # selects a stronger isolation boundary such as gVisor's runsc.
    sandbox_image: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
    sandbox_runtime: str = Field(default="docker", pattern=r"^[A-Za-z0-9._/-]+$")
    sandbox_oci_runtime: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]+$")
    sandbox_cpus: float = Field(default=0.5, gt=0, le=8)
    sandbox_memory_mb: int = Field(default=128, ge=16, le=8_192)
    sandbox_pids: int = Field(default=32, ge=1, le=1_024)
    sandbox_timeout_seconds: float = Field(default=10.0, gt=0, le=300)
    sandbox_output_bytes: int = Field(default=65_536, ge=1, le=10_000_000)
    # Section 7. Ask an Open Policy Agent server for every decision instead of
    # the built-in policy. The timeout is short: a decision is on the request
    # path, and a slow policy engine is treated as an unavailable one.
    opa_url: str | None = Field(default=None, pattern=r"^https?://")
    opa_timeout_seconds: float = Field(default=1.0, gt=0, le=10)
    # Section 14. Keep approvals and incident cases in PostgreSQL, or in a
    # SQLite file for one node. Unset, they live in memory and are lost on
    # restart. The URL may hold a password, so it is never logged.
    database_url: SecretStr | None = None
    # Sections 17 and 18. Export decision traces to an OTLP/HTTP collector.
    otlp_endpoint: str | None = Field(default=None, pattern=r"^https?://")

    # Section 15. When audit is mandatory, enforcement blocks once the outage
    # buffer is full; otherwise events beyond the bound are counted and dropped.
    audit_mandatory: bool = True
    # When the policy decision point is unreachable, side effects always fail
    # closed. This opts content inspection and read-only actions into the
    # built-in local policy instead of refusing them too.
    restricted_read_only_mode: bool = False

    # Sections 5, 8.1 and 8.4. Requests per minute for one identity and for a
    # whole tenant, and how many actions a single trace may propose.
    identity_requests_per_minute: int = Field(default=600, ge=1, le=1_000_000)
    tenant_requests_per_minute: int = Field(default=3_000, ge=1, le=10_000_000)
    max_actions_per_trace: int = Field(default=25, ge=1, le=10_000)

    # Section 8.1. Models content may be sent to; empty places no restriction.
    # Sensitive content bound for a local-only model is routed there unredacted
    # instead of being redacted for an external one.
    eligible_models: tuple[str, ...] = ()
    local_only_models: tuple[str, ...] = ()
    # Injection denials within the window that lock an identity out; 0 disables.
    violation_lockout_threshold: int = Field(default=0, ge=0, le=10_000)
    violation_window_seconds: int = Field(default=600, ge=1, le=86_400)

    # Section 8.3. Share of a cited sentence's terms its sources must contain,
    # phrases that count as declining to answer, and application-specific
    # categories of terms a response may not contain.
    grounding_min_overlap: float = Field(default=0.5, ge=0, le=1)
    abstention_phrases: tuple[str, ...] = (
        "i don't know",
        "i do not know",
        "i cannot answer",
        "i do not have enough information",
        "i don't have enough information",
    )
    disallowed_output_terms: dict[str, tuple[str, ...]] = Field(default_factory=dict)

    # Section 10. What is done with each sensitive category, for the deployment
    # and per tenant; an unlisted category is redacted. Secrets are never
    # allowed through or stored reversibly.
    sensitive_entity_actions: dict[str, EntityAction] = Field(default_factory=dict)
    tenant_entity_actions: dict[str, dict[str, EntityAction]] = Field(default_factory=dict)
    pseudonym_ttl_seconds: int = Field(default=3_600, ge=1, le=604_800)
    # Seeded values that must never appear anywhere; a sighting is a leak.
    canary_secrets: tuple[SecretStr, ...] = ()
    # A Presidio analyzer inside the trusted boundary, used when set.
    presidio_url: str | None = Field(default=None, pattern=r"^https?://")
    presidio_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    presidio_score_threshold: float = Field(default=0.5, ge=0, le=1)
    # A prompt-injection classifier inside the trusted boundary, used when
    # set: the /predict URL of a Hugging Face Text Embeddings Inference
    # server. The
    # labels are the ones its model uses for an injection; a score at or
    # above the threshold for any of them becomes evidence.
    injection_classifier_url: str | None = Field(default=None, pattern=r"^https?://")
    injection_classifier_labels: tuple[str, ...] = ("INJECTION", "JAILBREAK")
    injection_classifier_threshold: float = Field(default=0.9, gt=0, le=1)
    injection_classifier_timeout_seconds: float = Field(default=2.0, gt=0, le=30)

    # Section 11. Hosts an agent may fetch from, as a JSON list; empty permits
    # no outbound request. File tools are confined to one directory tree.
    allowed_url_hosts: tuple[str, ...] = ()
    file_root: str = Field(default="workspace", pattern=r"^[A-Za-z0-9_-]+$")

    # Signing material for caller credentials. There is deliberately no
    # "authentication disabled" switch: when this is unset the gateway cannot
    # prove who is calling, so it refuses every enforcement request instead of
    # trusting an identity asserted in a request body.
    jwt_secret: SecretStr | None = None
    jwt_algorithm: Literal["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"] = "HS256"
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    # Section 16. Verify against an OIDC identity provider instead of a
    # configured key: the issuer's signing keys are discovered and followed as
    # they rotate. `jwks_url` skips discovery for a provider without it.
    oidc_issuer: str | None = Field(default=None, pattern=r"^https?://[^\s]+$")
    jwks_url: str | None = Field(default=None, pattern=r"^https?://[^\s]+$")
    # How long fetched keys are used before they are fetched again, and how
    # long they may still be used when the provider cannot be reached. Past
    # that, a key revoked during the outage could still be trusted, so
    # verification stops instead.
    jwks_cache_seconds: int = Field(default=300, ge=10, le=86_400)
    jwks_max_stale_seconds: int = Field(default=3_600, ge=10, le=604_800)
    jwks_timeout_seconds: float = Field(default=3.0, gt=0, le=30)

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

    @model_validator(mode="after")
    def _keep_provider_keys_asymmetric(self) -> Self:
        if self.oidc_issuer is None and self.jwks_url is None:
            return self
        if self.jwt_algorithm.startswith("HS"):
            # A provider publishes public keys. Verifying an HMAC token with
            # one would let anyone who can read the key forge a credential.
            raise ValueError("an identity provider needs an RS256, RS384, or RS512 jwt_algorithm")
        if self.jwt_secret is not None:
            raise ValueError("configure jwt_secret or an identity provider, not both")
        if self.jwt_audience is None:
            # Without an audience, a token the provider issued for any other
            # application would be accepted here.
            raise ValueError("an identity provider needs jwt_audience")
        if self.jwt_issuer is None and self.oidc_issuer is None:
            raise ValueError("jwks_url needs jwt_issuer")
        return self

    @model_validator(mode="after")
    def _recognise_the_database(self) -> Self:
        if self.database_url is not None and not self.database_url.get_secret_value().startswith(
            ("postgresql://", "postgres://", "sqlite:///")
        ):
            raise ValueError("database_url must start with postgresql:// or sqlite:///")
        return self

    @model_validator(mode="after")
    def _keep_secrets_irreversible(self) -> Self:
        """Refuse a rule that would let a secret through or store it reversibly."""

        rules = [self.sensitive_entity_actions, *self.tenant_entity_actions.values()]
        for rule in rules:
            if rule.get("secret") in (EntityAction.ALLOW, EntityAction.PSEUDONYMIZE):
                raise ValueError("a secret may only be redacted or denied")
        # A short canary would match ordinary text and report leaks that are not.
        if any(len(c.get_secret_value()) < MINIMUM_CANARY_CHARS for c in self.canary_secrets):
            raise ValueError(f"a canary secret must be at least {MINIMUM_CANARY_CHARS} characters")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings object."""

    return Settings()
