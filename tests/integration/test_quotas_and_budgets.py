"""Quotas and execution budgets at the public boundary."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from guardrail_gateway.app import create_app
from guardrail_gateway.config import Settings
from guardrail_gateway.identity import Role, issue_token

pytestmark = pytest.mark.integration

CONTENT = {"identity": "user-1", "tenant_id": "acme", "content": "What is our refund policy?"}
TRACE = "11111111-1111-4111-8111-111111111111"
OTHER_TRACE = "22222222-2222-4222-8222-222222222222"


def _search(trace_id: str) -> dict[str, object]:
    return {
        "identity": "user-1",
        "tenant_id": "acme",
        "trace_id": trace_id,
        "tool": "search_documents",
        "resource": "tenant:acme:kb",
        "arguments": {"q": "refund"},
        "side_effect": "read",
    }


@contextmanager
def _gateway(settings: Settings, **limits: int) -> Iterator[TestClient]:
    with TestClient(create_app(settings.model_copy(update=limits))) as client:
        yield client


def _auth(settings: Settings, identity: str, tenant: str = "acme") -> dict[str, str]:
    token = issue_token(settings, identity, tenant, roles=(Role.CALLER, Role.OPERATOR))
    return {"Authorization": f"Bearer {token}"}


def test_an_identity_is_refused_past_its_quota(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(settings, identity_requests_per_minute=3) as client:
        verdicts = [
            client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT).json()
            for _ in range(4)
        ]

    assert [body["verdict"] for body in verdicts[:3]] == ["allow"] * 3
    assert verdicts[3]["verdict"] == "deny"
    assert verdicts[3]["reason_code"] == "quota_exceeded"


def test_one_identity_exhausting_its_quota_does_not_affect_another(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    other = {**CONTENT, "identity": "user-2"}

    with _gateway(settings, identity_requests_per_minute=1) as client:
        client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT)
        exhausted = client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT).json()
        neighbour = client.post(
            "/v1/inspect/input", headers=_auth(settings, "user-2"), json=other
        ).json()

    assert exhausted["reason_code"] == "quota_exceeded"
    assert neighbour["verdict"] == "allow"


def test_a_tenant_is_refused_past_its_shared_quota(settings: Settings) -> None:
    with _gateway(settings, tenant_requests_per_minute=2) as client:
        bodies = [
            client.post(
                "/v1/inspect/input",
                headers=_auth(settings, f"user-{index}"),
                json={**CONTENT, "identity": f"user-{index}"},
            ).json()
            for index in range(3)
        ]

    assert [body["verdict"] for body in bodies] == ["allow", "allow", "deny"]
    assert bodies[2]["reason_code"] == "quota_exceeded"


def test_one_tenant_exhausting_its_quota_does_not_affect_another(settings: Settings) -> None:
    with _gateway(settings, tenant_requests_per_minute=1) as client:
        client.post("/v1/inspect/input", headers=_auth(settings, "user-1"), json=CONTENT)
        exhausted = client.post(
            "/v1/inspect/input", headers=_auth(settings, "user-1"), json=CONTENT
        ).json()
        neighbour = client.post(
            "/v1/inspect/input",
            headers=_auth(settings, "user-1", "contoso"),
            json={**CONTENT, "tenant_id": "contoso"},
        ).json()

    assert exhausted["reason_code"] == "quota_exceeded"
    assert neighbour["verdict"] == "allow"


def test_quota_applies_to_actions_as_well_as_content(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(settings, identity_requests_per_minute=1) as client:
        client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT)
        body = client.post("/v1/inspect/action", headers=caller_auth, json=_search(TRACE)).json()

    assert body["reason_code"] == "quota_exceeded"


def test_a_trace_is_refused_past_its_execution_budget(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(settings, max_actions_per_trace=3) as client:
        bodies = [
            client.post("/v1/inspect/action", headers=caller_auth, json=_search(TRACE)).json()
            for _ in range(4)
        ]

    assert [body["verdict"] for body in bodies[:3]] == ["allow"] * 3
    assert bodies[3]["verdict"] == "deny"
    assert bodies[3]["reason_code"] == "execution_budget_exceeded"
    assert bodies[3]["action_digest"]


def test_a_new_trace_starts_with_a_fresh_budget(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(settings, max_actions_per_trace=1) as client:
        client.post("/v1/inspect/action", headers=caller_auth, json=_search(TRACE))
        spent = client.post("/v1/inspect/action", headers=caller_auth, json=_search(TRACE)).json()
        fresh = client.post(
            "/v1/inspect/action", headers=caller_auth, json=_search(OTHER_TRACE)
        ).json()

    assert spent["reason_code"] == "execution_budget_exceeded"
    assert fresh["verdict"] == "allow"


def test_refused_actions_spend_the_budget_too(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    refused = {**_search(TRACE), "tool": "run_shell", "arguments": {"cmd": "id"}}

    with _gateway(settings, max_actions_per_trace=2) as client:
        for _ in range(2):
            client.post("/v1/inspect/action", headers=caller_auth, json=refused)
        body = client.post("/v1/inspect/action", headers=caller_auth, json=_search(TRACE)).json()

    assert body["reason_code"] == "execution_budget_exceeded"


def test_one_tenant_cannot_spend_another_tenants_trace_budget(settings: Settings) -> None:
    foreign = {**_search(TRACE), "tenant_id": "contoso", "resource": "tenant:contoso:kb"}

    with _gateway(settings, max_actions_per_trace=1) as client:
        client.post(
            "/v1/inspect/action", headers=_auth(settings, "user-1", "contoso"), json=foreign
        )
        body = client.post(
            "/v1/inspect/action", headers=_auth(settings, "user-1"), json=_search(TRACE)
        ).json()

    assert body["verdict"] == "allow"
