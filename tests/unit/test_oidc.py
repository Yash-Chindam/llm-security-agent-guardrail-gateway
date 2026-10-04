"""Unit tests for verifying credentials against an identity provider's keys."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pydantic import ValidationError

from guardrail_gateway.config import Settings
from guardrail_gateway.identity import (
    AuthenticationFailure,
    CredentialError,
    IdentityVerifier,
    ProviderKeys,
    Role,
)

pytestmark = pytest.mark.unit

ISSUER = "https://idp.test/realms/acme"
JWKS_URL = "https://idp.test/realms/acme/keys"
AUDIENCE = "guardrail-gateway"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65_537, key_size=2_048)


KEY_A, KEY_B = _key(), _key()


def _jwk(key: rsa.RSAPrivateKey, key_id: str, **extra: Any) -> dict[str, Any]:
    return {**RSAAlgorithm.to_jwk(key.public_key(), as_dict=True), "kid": key_id, **extra}


def _token(
    key: rsa.RSAPrivateKey,
    key_id: str | None = "a",
    *,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    lifetime: int = 300,
) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": "user-1",
        "tenant": "acme",
        "roles": ["caller", "operator"],
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=lifetime),
    }
    headers = {"kid": key_id} if key_id is not None else None
    return "Bearer " + jwt.encode(claims, key, algorithm="RS256", headers=headers)


class Provider:
    """A stand-in identity provider whose keys and availability the test controls."""

    def __init__(self, *keys: dict[str, Any]) -> None:
        self.keys = list(keys)
        self.up = True
        self.discovery: dict[str, Any] = {"issuer": ISSUER, "jwks_uri": JWKS_URL}
        self.requests: list[str] = []
        self.now = 1_000.0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if not self.up:
            raise httpx.ConnectError("identity provider unreachable")
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.discovery)
        return httpx.Response(200, json={"keys": self.keys})

    def key_fetches(self) -> int:
        return self.requests.count(JWKS_URL)


def _settings(**changes: Any) -> Settings:
    return Settings(
        **{
            "jwt_algorithm": "RS256",
            "jwt_audience": AUDIENCE,
            "oidc_issuer": ISSUER,
            **changes,
        }
    )


def _verifier(provider: Provider, **changes: Any) -> IdentityVerifier:
    settings = _settings(**changes)
    client = httpx.Client(transport=httpx.MockTransport(provider))
    return IdentityVerifier(settings, ProviderKeys(settings, client, clock=lambda: provider.now))


def _refused(verifier: IdentityVerifier, credential: str) -> AuthenticationFailure:
    with pytest.raises(CredentialError) as raised:
        verifier.verify(credential)
    return raised.value.failure


def test_a_token_signed_by_a_discovered_key_is_accepted() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider)

    principal = verifier.verify(_token(KEY_A))

    assert (principal.identity, principal.tenant_id) == ("user-1", "acme")
    assert principal.roles == {Role.CALLER, Role.OPERATOR}
    assert provider.requests == [ISSUER + "/.well-known/openid-configuration", JWKS_URL]
    assert verifier.configured


def test_keys_are_cached_between_requests() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider)

    for _ in range(5):
        verifier.verify(_token(KEY_A))

    assert provider.key_fetches() == 1


def test_a_token_signed_by_another_key_is_refused() -> None:
    verifier = _verifier(Provider(_jwk(KEY_A, "a")))

    assert _refused(verifier, _token(KEY_B, "a")) is AuthenticationFailure.INVALID


def test_a_rotated_key_is_picked_up_without_waiting_for_the_cache() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider)
    verifier.verify(_token(KEY_A))

    provider.keys = [_jwk(KEY_B, "b")]
    provider.now += 60

    assert verifier.verify(_token(KEY_B, "b")).identity == "user-1"
    # The retired key is no longer published, so it is no longer trusted.
    assert _refused(verifier, _token(KEY_A, "a")) is AuthenticationFailure.INVALID


def test_unknown_key_ids_cannot_be_used_to_flood_the_provider() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider)
    verifier.verify(_token(KEY_A))

    for attempt in range(50):
        assert (
            _refused(verifier, _token(KEY_B, f"forged-{attempt}")) is AuthenticationFailure.INVALID
        )

    assert provider.key_fetches() == 1


def test_the_cache_is_refreshed_when_it_expires() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider, jwks_cache_seconds=300)
    verifier.verify(_token(KEY_A))

    provider.now += 301
    verifier.verify(_token(KEY_A))

    assert provider.key_fetches() == 2


def test_cached_keys_keep_working_through_a_short_provider_outage() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider, jwks_cache_seconds=300, jwks_max_stale_seconds=3_600)
    verifier.verify(_token(KEY_A))

    provider.up = False
    provider.now += 1_800

    assert verifier.verify(_token(KEY_A)).identity == "user-1"
    assert verifier.configured


def test_keys_are_not_trusted_past_the_staleness_limit() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider, jwks_cache_seconds=300, jwks_max_stale_seconds=3_600)
    verifier.verify(_token(KEY_A))

    provider.up = False
    provider.now += 3_901

    assert _refused(verifier, _token(KEY_A)) is AuthenticationFailure.UNAVAILABLE
    assert not verifier.configured

    provider.up = True
    provider.now += 11

    assert verifier.verify(_token(KEY_A)).identity == "user-1"


def test_a_provider_that_is_down_at_startup_fails_closed() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    provider.up = False
    verifier = _verifier(provider)

    assert not verifier.configured
    assert _refused(verifier, _token(KEY_A)) is AuthenticationFailure.UNAVAILABLE


def test_a_discovery_document_for_another_issuer_is_refused() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    provider.discovery = {"issuer": "https://evil.test", "jwks_uri": JWKS_URL}

    assert _refused(_verifier(provider), _token(KEY_A)) is AuthenticationFailure.UNAVAILABLE
    assert provider.key_fetches() == 0


def test_discovery_cannot_send_key_retrieval_over_plain_http() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    provider.discovery = {"issuer": ISSUER, "jwks_uri": "http://idp.test/keys"}

    assert _refused(_verifier(provider), _token(KEY_A)) is AuthenticationFailure.UNAVAILABLE


def test_a_malformed_key_set_is_not_trusted() -> None:
    provider = Provider()
    provider.keys = [{"kty": "RSA", "kid": "a", "n": "not-a-modulus"}]

    assert _refused(_verifier(provider), _token(KEY_A)) is AuthenticationFailure.UNAVAILABLE


def test_only_rsa_signing_keys_are_used() -> None:
    symmetric = {"kty": "oct", "kid": "a", "k": base64.urlsafe_b64encode(b"k" * 32).decode()}
    provider = Provider(symmetric, _jwk(KEY_A, "enc", use="enc"), _jwk(KEY_B, "b"))
    verifier = _verifier(provider)

    assert verifier.verify(_token(KEY_B, "b")).identity == "user-1"
    assert _refused(verifier, _token(KEY_A, "enc")) is AuthenticationFailure.INVALID


def test_a_public_key_cannot_be_used_as_an_hmac_secret() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider)
    public_pem = KEY_A.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = {"alg": "HS256", "typ": "JWT", "kid": "a"}
    claims = {
        "sub": "attacker",
        "tenant": "acme",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }

    def encode(part: dict[str, Any]) -> bytes:
        return base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=")

    import hashlib
    import hmac

    signing_input = encode(header) + b"." + encode(claims)
    signature = base64.urlsafe_b64encode(
        hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    ).rstrip(b"=")
    forged = "Bearer " + (signing_input + b"." + signature).decode()

    assert _refused(verifier, forged) is AuthenticationFailure.INVALID


def test_an_unsigned_token_is_refused() -> None:
    verifier = _verifier(Provider(_jwk(KEY_A, "a")))

    def encode(part: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=").decode()

    unsigned = encode({"alg": "none", "kid": "a"}) + "." + encode({"sub": "attacker"}) + "."

    assert _refused(verifier, "Bearer " + unsigned) is AuthenticationFailure.INVALID


def test_a_token_that_is_not_a_jwt_is_refused() -> None:
    verifier = _verifier(Provider(_jwk(KEY_A, "a")))

    assert _refused(verifier, "Bearer not-a-token") is AuthenticationFailure.INVALID


@pytest.mark.parametrize(
    "changes",
    [{"issuer": "https://other-idp.test"}, {"audience": "another-application"}],
)
def test_a_token_for_another_issuer_or_application_is_refused(changes: dict[str, str]) -> None:
    verifier = _verifier(Provider(_jwk(KEY_A, "a")))

    assert _refused(verifier, _token(KEY_A, **changes)) is AuthenticationFailure.INVALID


def test_an_expired_token_is_refused() -> None:
    verifier = _verifier(Provider(_jwk(KEY_A, "a")))

    assert _refused(verifier, _token(KEY_A, lifetime=-60)) is AuthenticationFailure.EXPIRED


def test_a_token_naming_no_key_is_accepted_only_when_there_is_one_key() -> None:
    single = _verifier(Provider(_jwk(KEY_A, "a")))
    several = _verifier(Provider(_jwk(KEY_A, "a"), _jwk(KEY_B, "b")))

    assert single.verify(_token(KEY_A, None)).identity == "user-1"
    assert _refused(several, _token(KEY_A, None)) is AuthenticationFailure.INVALID


def test_a_key_url_can_be_given_without_discovery() -> None:
    provider = Provider(_jwk(KEY_A, "a"))
    verifier = _verifier(provider, oidc_issuer=None, jwks_url=JWKS_URL, jwt_issuer=ISSUER)

    assert verifier.verify(_token(KEY_A)).identity == "user-1"
    assert provider.requests == [JWKS_URL]


def test_closing_the_verifier_closes_its_client() -> None:
    verifier = IdentityVerifier(_settings())

    assert verifier._provider is not None
    verifier.close()

    assert verifier._provider._client.is_closed


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"jwt_algorithm": "HS256"}, "RS256"),
        ({"jwt_secret": "x" * 40}, "not both"),
        ({"jwt_audience": None}, "jwt_audience"),
        ({"oidc_issuer": None, "jwks_url": JWKS_URL}, "jwt_issuer"),
        ({"oidc_issuer": "ftp://idp.test"}, "oidc_issuer"),
    ],
)
def test_an_unsafe_provider_configuration_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _settings(**changes)
