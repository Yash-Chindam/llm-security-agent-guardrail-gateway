from guardrail_gateway.models import ActionInspectionRequest, SideEffect
from guardrail_gateway.policy import action_digest, action_verdict


def _action(**overrides: object) -> ActionInspectionRequest:
    payload: dict[str, object] = {
        "identity": "user-1",
        "tenant_id": "acme",
        "tool": "execute_sql",
        "resource": "tenant:acme:analytics",
        "arguments": {"query": "SELECT id FROM reports"},
        "side_effect": SideEffect.READ,
    }
    payload.update(overrides)
    return ActionInspectionRequest.model_validate(payload)


def test_action_digest_is_canonical() -> None:
    first = _action(arguments={"query": "SELECT id FROM reports", "limit": 10})
    second = _action(arguments={"limit": 10, "query": "SELECT id FROM reports"})

    assert action_digest(first) == action_digest(second)


def test_denies_cross_tenant_resource() -> None:
    verdict, reason = action_verdict(_action(resource="tenant:other:analytics"))

    assert verdict.value == "deny"
    assert reason == "resource_tenant_mismatch"


def test_denies_mutating_sql_even_if_claimed_read_only() -> None:
    verdict, reason = action_verdict(_action(arguments={"query": "SELECT 1; DROP TABLE customers"}))

    assert verdict.value == "deny"
    assert reason == "sql_not_read_only"
