"""Verified caller identity for identity-aware policy decisions.

Section 4 of the design specification requires identity-aware policy and
section 16 requires OIDC/OAuth identity. The gateway therefore never trusts an
identity asserted in a request body: the principal is derived from a signed
bearer token, and any identity the body claims must agree with it.

Verification is local and offline. The deployment supplies the signing material
(a shared secret for HMAC, or the issuer's public key for RSA), so the gateway
keeps enforcing while the identity provider is unreachable and fails closed
when no material is configured at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt

from guardrail_gateway.config import Settings

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

    def has_role(self, role: Role) -> bool:
        return role in self.roles


class IdentityVerifier:
    """Turns a bearer credential into a Principal, or refuses with a reason."""

    def __init__(self, settings: Settings) -> None:
        secret = settings.jwt_secret
        self._key = secret.get_secret_value() if secret is not None else None
        self._algorithm = settings.jwt_algorithm
        self._issuer = settings.jwt_issuer
        self._audience = settings.jwt_audience

    @property
    def configured(self) -> bool:
        """False when no signing material is available, so nothing can be trusted."""

        return bool(self._key)

    def verify(self, credential: str | None) -> Principal:
        """Verify an Authorization header value and return its principal."""

        if self._key is None:
            # Fail closed: without signing material no identity can be proven,
            # and an unauthenticated caller must never reach an enforcement point.
            raise CredentialError(AuthenticationFailure.UNAVAILABLE)

        token = _bearer_token(credential)
        claims = self._decode(token, self._key)
        return _principal_from(claims)

    def _decode(self, token: str, key: str) -> dict[str, Any]:
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
    return Principal(identity=subject, tenant_id=tenant, roles=roles)


def issue_token(
    settings: Settings,
    identity: str,
    tenant_id: str,
    roles: tuple[Role, ...] = (Role.CALLER,),
    lifetime_seconds: int = 300,
    issued_at: datetime | None = None,
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
        "iat": now,
        "exp": now + timedelta(seconds=lifetime_seconds),
    }
    if settings.jwt_issuer is not None:
        claims["iss"] = settings.jwt_issuer
    if settings.jwt_audience is not None:
        claims["aud"] = settings.jwt_audience
    return jwt.encode(claims, secret.get_secret_value(), algorithm=settings.jwt_algorithm)
