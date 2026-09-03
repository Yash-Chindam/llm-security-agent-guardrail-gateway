from guardrail_gateway.detectors import DECODED_DETECTOR
from guardrail_gateway.models import (
    ActionInspectionRequest,
    DetectorEvidence,
    EnforcementPoint,
    SideEffect,
    TrustLevel,
)
from guardrail_gateway.policy import action_digest, action_verdict, content_verdict


def _evidence(detector: str, category: str) -> DetectorEvidence:
    return DetectorEvidence(
        detector=detector,
        version="1.1.0",
        category=category,
        score=0.9,
        threshold=0.8,
        redacted_excerpt="[MATCH]",
        explanation="test evidence",
    )


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


def test_denies_content_recovered_only_after_decoding_regardless_of_category() -> None:
    evidence = [_evidence(DECODED_DETECTOR, "prompt_injection")]

    verdict, reason = content_verdict(
        EnforcementPoint.INPUT, TrustLevel.TRUSTED, None, "acme", evidence
    )

    assert verdict.value == "deny"
    assert reason == "obfuscated_content_detected"


def test_denies_jailbreak_content_in_an_untrusted_context() -> None:
    evidence = [_evidence("deterministic_content", "jailbreak")]

    verdict, reason = content_verdict(
        EnforcementPoint.CONTEXT, TrustLevel.UNTRUSTED, None, "acme", evidence
    )

    assert verdict.value == "deny"
    assert reason == "prompt_injection_detected"


def test_allows_jailbreak_wording_in_trusted_input() -> None:
    evidence = [_evidence("deterministic_content", "jailbreak")]

    verdict, reason = content_verdict(
        EnforcementPoint.INPUT, TrustLevel.TRUSTED, None, "acme", evidence
    )

    assert verdict.value == "allow"
    assert reason == "policy_allow"
