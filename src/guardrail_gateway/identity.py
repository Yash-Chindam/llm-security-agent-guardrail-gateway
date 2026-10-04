"""Verified caller identity for identity-aware policy decisions.

Section 4 of the design specification requires identity-aware policy and
section 16 requires OIDC/OAuth identity. The gateway therefore never trusts an
identity asserted in a request body: the principal is derived from a signed
bearer token, and any identity the body claims must agree with it.

Verification is local. The signing material is either configured (a shared
secret for HMAC, or the issuer's public key for RSA) or discovered from an OIDC
identity provider and followed as its keys rotate. Either way the gateway
keeps enforcing while the provider is briefly unreachable, and fails closed
when it has no key it can still trust.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from time import monotonic
from typing import Any

import httpx
import jwt

from guardrail_gateway.config import Settings
from guardrail_gateway.models import Classification

_BEARER_PREFIX = "bearer "

# Algorithms the gateway will verify. The decode call is always pinned to the
# single configured algorithm, so a token cannot select its own verification
# scheme ("alg": "none") or downgrade an RSA key to an HMAC secret.
SUPPORTED_ALGORITHMS = frozenset({"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"})


class Role(StrEnum):
    """Authorization roles read from the token's ``roles`` claim."""

    CALLER = "caller"
    # May propose tools that have a side effect, subject to approval.
    OPERATOR = "operator"
    REVIEWER = "reviewer"
    # May read decisions and incident cases, and change nothing.
    AUDITOR = "auditor"


class AuthenticationFailure(StrEnum):
    """Reason codes for a refused credential. Safe to return to the caller."""

    UNAVAILABLE = "identity_verification_unavailable"
    MISSING = "credentials_missing"
    INVALID = "credentials_invalid"
    EXPIRED = "credentials_expired"
    INCOMPLETE = "credentials_incomplete"


class CredentialError(Exception):
    """Raised when a credential cannot be turned into a trusted principal."""

    def __init__(self, failure: AuthenticationFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller. Only a verifier may construct a trusted one."""

    identity: str
    tenant_id: str
    roles: frozenset[Role]
    # The most sensitive classification this caller may read.
    clearance: Classification = Classification.INTERNAL

    def has_role(self, role: Role) -> bool:
        return role in self.roles


# After a fetch, how long before an unknown key id may trigger another. A
# caller can put any key id in a token, so without this every forged token
# would cost the identity provider a request.
_MIN_REFRESH_SECONDS = 10.0
_DISCOVERY_PATH = "/.well-known/openid-configuration"


class ProviderKeys:
    """The identity provider's current signing keys, by key id.

    Keys are fetched on first use, again when the cache expires, and again
    when a token names a key id that is not known, which is how a rotation is
    picked up without waiting for the cache. When the provider cannot be
    reached the last keys stay in use up to the staleness limit.
    """

    def __init__(
        self,
        settings: Settings,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._issuer = settings.oidc_issuer
        self._jwks_url = settings.jwks_url
        self._cache_seconds = settings.jwks_cache_seconds
        self._max_stale_seconds = settings.jwks_max_stale_seconds
        self._client = client or httpx.Client(timeout=settings.jwks_timeout_seconds)
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._lock = RLock()

    def close(self) -> None:
        self._client.close()

    def usable(self) -> bool:
        with self._lock:
            self._refresh_if_due()
            return self._trusted()

    def key_for(self, token: str) -> Any:
        """The public key that should have signed this token."""

        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as error:
            raise CredentialError(AuthenticationFailure.INVALID) from error
        key_id = header.get("kid")
        with self._lock:
            self._refresh_if_due()
            if isinstance(key_id, str) and key_id not in self._keys:
                self._refresh()
            if not self._trusted():
                raise CredentialError(AuthenticationFailure.UNAVAILABLE)
            if isinstance(key_id, str):
                key = self._keys.get(key_id)
            else:
                # A token that names no key is only unambiguous when the
                # provider publishes exactly one.
                key = next(iter(self._keys.values())) if len(self._keys) == 1 else None
        if key is None:
            raise CredentialError(AuthenticationFailure.INVALID)
        return key

    def _trusted(self) -> bool:
        if self._fetched_at is None or not self._keys:
            return False
        return self._clock() - self._fetched_at <= self._cache_seconds + self._max_stale_seconds

    def _refresh_if_due(self) -> None:
        if self._fetched_at is None or self._clock() - self._fetched_at >= self._cache_seconds:
            self._refresh()

    def _refresh(self) -> None:
        now = self._clock()
        if self._attempted_at is not None and now - self._attempted_at < _MIN_REFRESH_SECONDS:
            return
        self._attempted_at = now
        try:
            keys = self._fetch()
        except (httpx.HTTPError, ValueError, KeyError, TypeError, jwt.PyJWTError):
            # The previous keys stay in use until the staleness limit.
            return
        if keys:
            self._keys = keys
            self._fetched_at = now

    def _fetch(self) -> dict[str, Any]:
        url = self._jwks_url or self._discover()
        response = self._client.get(url)
        response.raise_for_status()
        keys: dict[str, Any] = {}
        for entry in response.json()["keys"]:
            # Only RSA keys published for signing. An encryption key, or a
            # symmetric one, must never verify a credential.
            if entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig":
                continue
            key_id = entry.get("kid")
            if isinstance(key_id, str) and key_id:
                keys[key_id] = jwt.PyJWK.from_dict(entry).key
        return keys

    def _discover(self) -> str:
        if self._issuer is None:  # pragma: no cover - settings require one of the two
            raise ValueError("no issuer")
        issuer = self._issuer.rstrip("/")
        response = self._client.get(issuer + _DISCOVERY_PATH)
        response.raise_for_status()
        document = response.json()
        # The document must describe the issuer that was asked for, and may
        # not send key retrieval over a weaker scheme than discovery used.
        if str(document["issuer"]).rstrip("/") != issuer:
            raise ValueError("issuer mismatch")
        jwks_uri = str(document["jwks_uri"])
        if issuer.startswith("https://") and not jwks_uri.startswith("https://"):
            raise ValueError("jwks_uri is not https")
        return jwks_uri


class IdentityVerifier:
    """Turns a bearer credential into a Principal, or refuses with a reason."""

    def __init__(self, settings: Settings, provider: ProviderKeys | None = None) -> None:
        secret = settings.jwt_secret
        self._key = secret.get_secret_value() if secret is not None else None
        self._algorithm = settings.jwt_algorithm
        self._issuer = settings.jwt_issuer or settings.oidc_issuer
        self._audience = settings.jwt_audience
        self._provider = provider
        if provider is None and (settings.oidc_issuer or settings.jwks_url):
            self._provider = ProviderKeys(settings)

    @property
    def configured(self) -> bool:
        """False when no signing material is available, so nothing can be trusted."""

        if self._provider is not None:
            return self._provider.usable()
        return bool(self._key)

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()

    def verify(self, credential: str | None) -> Principal:
        """Verify an Authorization header value and return its principal."""

        if self._provider is None and self._key is None:
            # Fail closed: without signing material no identity can be proven,
            # and an unauthenticated caller must never reach an enforcement point.
            raise CredentialError(AuthenticationFailure.UNAVAILABLE)

        token = _bearer_token(credential)
        key = self._provider.key_for(token) if self._provider is not None else self._key
        claims = self._decode(token, key)
        return _principal_from(claims)

    def _decode(self, token: str, key: Any) -> dict[str, Any]:
        try:
            decoded: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
                # An unexpired token that names its subject is the minimum the
                # gateway will act on, whatever else the issuer chose to send.
                options={"require": ["exp", "sub"]},
            )
        except jwt.ExpiredSignatureError as error:
            raise CredentialError(AuthenticationFailure.EXPIRED) from error
        except jwt.MissingRequiredClaimError as error:
            raise CredentialError(AuthenticationFailure.INCOMPLETE) from error
        except jwt.InvalidTokenError as error:
            # Covers a bad signature, a wrong algorithm, and a rejected
            # issuer or audience. The caller never learns which.
            raise CredentialError(AuthenticationFailure.INVALID) from error
        return decoded


def _bearer_token(credential: str | None) -> str:
    if not credential or not credential.lower().startswith(_BEARER_PREFIX):
        raise CredentialError(AuthenticationFailure.MISSING)
    token = credential[len(_BEARER_PREFIX) :].strip()
    if not token:
        raise CredentialError(AuthenticationFailure.MISSING)
    return token


def _principal_from(claims: dict[str, Any]) -> Principal:
    subject = claims.get("sub")
    tenant = claims.get("tenant")
    if not isinstance(subject, str) or not subject:
        raise CredentialError(AuthenticationFailure.INCOMPLETE)
    if not isinstance(tenant, str) or not tenant:
        raise CredentialError(AuthenticationFailure.INCOMPLETE)

    claimed = claims.get("roles")
    values = claimed if isinstance(claimed, list) else []
    # Unknown role names are dropped rather than rejected, so an identity
    # provider can carry roles this gateway does not use.
    roles = frozenset(Role(value) for value in values if value in set(Role))
    claimed_clearance = claims.get("clearance", Classification.INTERNAL.value)
    # An unrecognised clearance grants the least, never a default above it.
    clearance = (
        Classification(claimed_clearance)
        if claimed_clearance in set(Classification)
        else Classification.PUBLIC
    )
    return Principal(identity=subject, tenant_id=tenant, roles=roles, clearance=clearance)


def issue_token(
    settings: Settings,
    identity: str,
    tenant_id: str,
    roles: tuple[Role, ...] = (Role.CALLER,),
    lifetime_seconds: int = 300,
    issued_at: datetime | None = None,
    clearance: Classification = Classification.INTERNAL,
) -> str:
    """Mint a credential for the adversarial suite and local development.

    Production deployments receive tokens from an external identity provider;
    the gateway itself only ever verifies them. This helper exists so the
    red-team suite and the test layers can authenticate against a deployment
    whose signing material they already hold.
    """

    secret = settings.jwt_secret
    if secret is None:
        raise ValueError("no signing material configured")

    now = issued_at or datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": identity,
        "tenant": tenant_id,
        "roles": [role.value for role in roles],
        "clearance": clearance.value,
        "iat": now,
        "exp": now + timedelta(seconds=lifetime_seconds),
    }
    if settings.jwt_issuer is not None:
        claims["iss"] = settings.jwt_issuer
    if settings.jwt_audience is not None:
        claims["aud"] = settings.jwt_audience
    return jwt.encode(claims, secret.get_secret_value(), algorithm=settings.jwt_algorithm)
