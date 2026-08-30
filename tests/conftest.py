from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from guardrail_gateway.app import create_app
from guardrail_gateway.config import Settings


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(Settings(policy_version="test-policy", approval_ttl_seconds=60))
    with TestClient(app) as test_client:
        yield test_client
