from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from guardrail_gateway.app import create_app
from guardrail_gateway.config import Settings
from guardrail_gateway.identity import Role, issue_token

TEST_SIGNING_KEY = "test-signing-key-0123456789abcdef-not-a-deployment-secret"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        policy_version="test-policy",
        approval_ttl_seconds=60,
        jwt_secret=TEST_SIGNING_KEY,
        jwt_issuer="https://issuer.test",
        jwt_audience="guardrail-gateway",
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def caller_token(settings: Settings) -> str:
    return issue_token(settings, "user-1", "acme")


@pytest.fixture
def reviewer_token(settings: Settings) -> str:
    return issue_token(settings, "reviewer-1", "acme", roles=(Role.CALLER, Role.REVIEWER))


@pytest.fixture
def caller_auth(caller_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {caller_token}"}


@pytest.fixture
def reviewer_auth(reviewer_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {reviewer_token}"}
