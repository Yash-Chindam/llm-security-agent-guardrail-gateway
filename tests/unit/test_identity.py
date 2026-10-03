"""Unit tests for credential verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from guardrail_gateway.config import Settings
from guardrail_gateway.identity import (
    AuthenticationFailure,
    CredentialError,
    IdentityVerifier,
    Role,
    issue_token,
)

pytestmark = pytest.mark.unit

KEY = "unit-test-signing-key-0123456789abcdef"


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "jwt_secret": KEY,
        "jwt_issuer": "https://issuer.test",
        "jwt_audience": "guardrail-gateway",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _bearer(token: str) -> str:
    return f"Bearer {token}"


def test_a_valid_credential_yields_its_principal() -> None:
    settings = _settings()
    token = issue_token(settings, "svc.agent@acme", "acme", roles=(Role.CALLER, Role.REVIEWER))

    principal = IdentityVerifier(settings).verify(_bearer(token))

    assert principal.identity == "svc.agent@acme"
    assert principal.tenant_id == "acme"
    assert principal.has_role(Role.REVIEWER)


def test_verification_is_unavailable_without_signing_material() -> None:
    verifier = IdentityVerifier(Settings())

    assert not verifier.configured
    with pytest.raises(CredentialError) as error:
        verifier.verify(_bearer("anything"))
    assert error.value.failure is AuthenticationFailure.UNAVAILABLE


@pytest.mark.parametrize("header", [None, "", "Token abc", "Bearer", "Bearer    "])
def test_a_non_bearer_header_is_missing_credentials(header: str | None) -> None:
    with pytest.raises(CredentialError) as error:
        IdentityVerifier(_settings()).verify(header)

    assert error.value.failure is AuthenticationFailure.MISSING


def test_the_bearer_scheme_is_case_insensitive() -> None:
    settings = _settings()
    token = issue_token(settings, "user-1", "acme")

    principal = IdentityVerifier(settings).verify(f"bEaReR {token}")

    assert principal.identity == "user-1"


def test_a_credential_signed_with_another_key_is_invalid() -> None:
    forged = issue_token(
        _settings(jwt_secret="another-key-0123456789abcdef-padding"), "user-1", "acme"
    )

    with pytest.raises(CredentialError) as error:
        IdentityVerifier(_settings()).verify(_bearer(forged))

    assert error.value.failure is AuthenticationFailure.INVALID


def test_an_expired_credential_is_refused() -> None:
    settings = _settings()
    issued = datetime.now(UTC) - timedelta(hours=1)
    token = issue_token(settings, "user-1", "acme", lifetime_seconds=60, issued_at=issued)

    with pytest.raises(CredentialError) as error:
        IdentityVerifier(settings).verify(_bearer(token))

    assert error.value.failure is AuthenticationFailure.EXPIRED


def test_an_unsigned_credential_cannot_select_its_own_algorithm() -> None:
    """A token asking to be verified with "none" must not bypass the signature."""

    claims = {
        "sub": "user-1",
        "tenant": "acme",
        "iss": "https://issuer.test",
        "aud": "guardrail-gateway",
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }
    unsigned = jwt.encode(claims, key="", algorithm="none")

    with pytest.raises(CredentialError) as error:
        IdentityVerifier(_settings()).verify(_bearer(unsigned))

    assert error.value.failure is AuthenticationFailure.INVALID


def test_a_credential_from_another_issuer_is_refused() -> None:
    other = issue_token(_settings(jwt_issuer="https://attacker.test"), "user-1", "acme")

    with pytest.raises(CredentialError) as error:
        IdentityVerifier(_settings()).verify(_bearer(other))

    assert error.value.failure is AuthenticationFailure.INVALID


def test_a_credential_for_another_audience_is_refused() -> None:
    other = issue_token(_settings(jwt_audience="some-other-service"), "user-1", "acme")

    with pytest.raises(CredentialError) as error:
        IdentityVerifier(_settings()).verify(_bearer(other))

    assert error.value.failure is AuthenticationFailure.INVALID


@pytest.mark.parametrize("missing", ["sub", "tenant"])
def test_a_credential_without_identity_or_tenant_is_incomplete(missing: str) -> None:
    settings = _settings()
    claims: dict[str, object] = {
        "sub": "user-1",
        "tenant": "acme",
        "iss": "https://issuer.test",
        "aud": "guardrail-gateway",
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }
    claims.pop(missing)
    token = jwt.encode(claims, KEY, algorithm="HS256")

    with pytest.raises(CredentialError) as error:
        IdentityVerifier(settings).verify(_bearer(token))

    assert error.value.failure is AuthenticationFailure.INCOMPLETE


def test_a_credential_without_an_expiry_is_incomplete() -> None:
    token = jwt.encode(
        {
            "sub": "user-1",
            "tenant": "acme",
            "iss": "https://issuer.test",
            "aud": "guardrail-gateway",
        },
        KEY,
        algorithm="HS256",
    )

    with pytest.raises(CredentialError) as error:
        IdentityVerifier(_settings()).verify(_bearer(token))

    assert error.value.failure is AuthenticationFailure.INCOMPLETE


def test_unknown_roles_are_dropped_rather_than_rejected() -> None:
    settings = _settings()
    token = jwt.encode(
        {
            "sub": "user-1",
            "tenant": "acme",
            "roles": ["caller", "billing-admin"],
            "iss": "https://issuer.test",
            "aud": "guardrail-gateway",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        KEY,
        algorithm="HS256",
    )

    principal = IdentityVerifier(settings).verify(_bearer(token))

    assert principal.roles == frozenset({Role.CALLER})


def test_a_non_list_roles_claim_yields_no_roles() -> None:
    settings = _settings()
    token = jwt.encode(
        {
            "sub": "user-1",
            "tenant": "acme",
            "roles": "reviewer",
            "iss": "https://issuer.test",
            "aud": "guardrail-gateway",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        KEY,
        algorithm="HS256",
    )

    principal = IdentityVerifier(settings).verify(_bearer(token))

    assert principal.roles == frozenset()
    assert not principal.has_role(Role.REVIEWER)


def test_issuing_a_token_without_signing_material_fails_loudly() -> None:
    with pytest.raises(ValueError, match="no signing material"):
        issue_token(Settings(), "user-1", "acme")


def test_the_signing_key_is_not_exposed_by_the_settings_repr() -> None:
    assert KEY not in repr(_settings())


def test_a_weak_shared_secret_is_a_configuration_error() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        Settings(jwt_secret="too-short")

    # An asymmetric key is validated by the signing library, not by length here.
    assert Settings(jwt_secret="short-but-rsa", jwt_algorithm="RS256").jwt_secret is not None


def test_clearance_defaults_to_internal_and_is_read_from_the_credential() -> None:
    from guardrail_gateway.models import Classification

    settings = _settings()
    default = issue_token(settings, "user-1", "acme")
    cleared = issue_token(settings, "user-1", "acme", clearance=Classification.RESTRICTED)
    verifier = IdentityVerifier(settings)

    assert verifier.verify(_bearer(default)).clearance is Classification.INTERNAL
    assert verifier.verify(_bearer(cleared)).clearance is Classification.RESTRICTED
