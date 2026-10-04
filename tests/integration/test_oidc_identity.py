"""An identity provider's keys behind the HTTP API."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from guardrail_gateway.app import create_app
from guardrail_gateway.config import Settings
from guardrail_gateway.identity import IdentityVerifier, ProviderKeys

pytestmark = pytest.mark.integration

ISSUER = "https://idp.test/realms/acme"
JWKS_URL = ISSUER + "/keys"
KEY = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
ROGUE = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
CONTENT = {"identity": "user-1", "tenant_id": "acme", "content": "What is our refund policy?"}


class Provider:
    def __init__(self) -> None:
        self.up = True

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if not self.up:
            raise httpx.ConnectError("identity provider unreachable")
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS_URL})
        jwk = {**RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True), "kid": "current"}
        return httpx.Response(200, json={"keys": [jwk]})


def _auth(key: rsa.RSAPrivateKey, **claims: Any) -> dict[str, str]:
    now = datetime.now(UTC)
    body = {
        "sub": "user-1",
        "tenant": "acme",
        "roles": ["caller"],
        "iss": ISSUER,
        "aud": "guardrail-gateway",
        "exp": now + timedelta(minutes=5),
        **claims,
    }
    token = jwt.encode(body, key, algorithm="RS256", headers={"kid": "current"})
    return {"Authorization": f"Bearer {token}"}


def _gateway(provider: Provider) -> TestClient:
    settings = Settings(
        policy_version="test-policy",
        jwt_algorithm="RS256",
        jwt_audience="guardrail-gateway",
        oidc_issuer=ISSUER,
    )
    client = httpx.Client(transport=httpx.MockTransport(provider))
    verifier = IdentityVerifier(settings, ProviderKeys(settings, client))
    return TestClient(create_app(settings, identity_verifier=verifier))


def test_a_caller_with_a_provider_issued_token_is_served() -> None:
    with _gateway(Provider()) as client:
        response = client.post("/v1/inspect/input", headers=_auth(KEY), json=CONTENT)
        ready = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["verdict"] == "allow"
    assert ready.status_code == 200
    assert ready.json()["identity_verification"] == "configured"


def test_a_token_from_a_key_the_provider_does_not_publish_is_refused() -> None:
    with _gateway(Provider()) as client:
        response = client.post("/v1/inspect/input", headers=_auth(ROGUE), json=CONTENT)

    assert response.status_code == 401
    assert response.json()["detail"] == "credentials_invalid"


def test_the_body_cannot_claim_a_tenant_the_token_does_not_carry() -> None:
    with _gateway(Provider()) as client:
        response = client.post(
            "/v1/inspect/input", headers=_auth(KEY), json={**CONTENT, "tenant_id": "other"}
        )

    assert response.json()["reason_code"] == "identity_assertion_mismatch"


def test_an_unreachable_provider_at_startup_refuses_every_request_and_is_not_ready() -> None:
    provider = Provider()
    provider.up = False

    with _gateway(provider) as client:
        response = client.post("/v1/inspect/input", headers=_auth(KEY), json=CONTENT)
        ready = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["detail"] == "identity_verification_unavailable"
    assert ready.status_code == 503
    assert ready.json()["identity_verification"] == "unavailable"


def test_configuring_an_issuer_builds_a_provider_backed_verifier() -> None:
    settings = Settings(jwt_algorithm="RS256", jwt_audience="guardrail-gateway", oidc_issuer=ISSUER)

    with TestClient(create_app(settings)) as client:
        verifier = client.app.state.identity_verifier  # type: ignore[attr-defined]

        assert verifier._provider is not None
    assert verifier._provider._client.is_closed
