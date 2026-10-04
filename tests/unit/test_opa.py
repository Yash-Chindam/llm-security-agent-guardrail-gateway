"""Unit tests for the OPA policy adapter, driven without an OPA server."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import DECODED_DETECTOR
from guardrail_gateway.identity import Role
from guardrail_gateway.models import (
    ActionInspectionRequest,
    DetectorEvidence,
    EnforcementPoint,
    EntityAction,
    SideEffect,
    TrustLevel,
    Verdict,
)
from guardrail_gateway.opa import ACTION_PATH, CONTENT_PATH, OpaPolicyEngine, tool_registry_data
from guardrail_gateway.policy import PolicyEngineUnavailableError, policy_available

pytestmark = pytest.mark.unit

BUNDLE = Path(__file__).resolve().parents[2] / "deploy" / "opa" / "policy"
SECRET_EMAIL = "pat.doe@example.com"
ALLOW = {"result": {"verdict": "allow", "reason_code": "policy_allow"}}
Handler = Callable[[httpx.Request], httpx.Response]


def _evidence(category: str, detector: str = "deterministic") -> DetectorEvidence:
    return DetectorEvidence(
        detector=detector,
        version="1",
        category=category,
        score=0.9,
        threshold=0.8,
        redacted_excerpt=f"contact {SECRET_EMAIL} today",
        explanation="Detected.",
    )


def _action(**changes: Any) -> ActionInspectionRequest:
    fields: dict[str, Any] = {
        "identity": "user-1",
        "tenant_id": "acme",
        "tool": "execute_sql",
        "resource": "tenant:acme:analytics",
        "arguments": {"query": "SELECT count(*) FROM orders"},
        "side_effect": SideEffect.READ,
    }
    return ActionInspectionRequest(**{**fields, **changes})


def _engine(settings: Settings, handler: Handler) -> OpaPolicyEngine:
    configured = settings.model_copy(update={"opa_url": "http://opa:8181"})
    client = httpx.Client(base_url="http://opa:8181", transport=httpx.MockTransport(handler))
    return OpaPolicyEngine(configured, client)


def _answering(body: Any, status: int = 200) -> tuple[Handler, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body)

    return handler, seen


def _content(engine: OpaPolicyEngine, *evidence: DetectorEvidence) -> tuple[Verdict, str]:
    return engine.content_verdict(
        EnforcementPoint.INPUT, TrustLevel.UNTRUSTED, None, "acme", list(evidence)
    )


def test_content_is_described_to_opa_by_category_and_never_by_value(settings: Settings) -> None:
    handler, seen = _answering(
        {"result": {"verdict": "transform", "reason_code": "sensitive_content_redacted"}}
    )
    configured = settings.model_copy(
        update={"sensitive_entity_actions": {"pii_email": EntityAction.PSEUDONYMIZE}}
    )

    decision = _engine(configured, handler).content_verdict(
        EnforcementPoint.CONTEXT,
        TrustLevel.TRUSTED,
        "acme",
        "acme",
        [_evidence("pii_email"), _evidence("secret", DECODED_DETECTOR)],
    )

    assert decision == (Verdict.TRANSFORM, "sensitive_content_redacted")
    assert seen[0].url.path == CONTENT_PATH
    assert json.loads(seen[0].content) == {
        "input": {
            "enforcement_point": "context",
            "trust_level": "trusted",
            "source_tenant_id": "acme",
            "tenant_id": "acme",
            "evidence": [
                {"category": "pii_email", "obfuscated": False},
                {"category": "secret", "obfuscated": True},
            ],
            "entity_actions": {"pii_email": "pseudonymize", "secret": "redact"},
        }
    }
    assert SECRET_EMAIL.encode() not in seen[0].content


def test_an_action_is_described_by_a_digest_and_never_by_its_arguments(
    settings: Settings,
) -> None:
    handler, seen = _answering(
        {"result": {"verdict": "allow", "reason_code": "action_policy_allow"}}
    )
    request = _action()

    decision = _engine(settings, handler).action_verdict(
        request, frozenset({Role.OPERATOR, Role.CALLER})
    )

    assert decision == (Verdict.ALLOW, "action_policy_allow")
    assert seen[0].url.path == ACTION_PATH
    document = json.loads(seen[0].content)["input"]
    assert document == {
        "enforcement_point": "action",
        "identity": "user-1",
        "tenant_id": "acme",
        "roles": ["caller", "operator"],
        "tool": "execute_sql",
        "resource": "tenant:acme:analytics",
        "side_effect": "read",
        "argument_digest": document["argument_digest"],
        "facts": {"argument_violation": None},
    }
    assert len(document["argument_digest"]) == 64
    assert b"SELECT" not in seen[0].content


def test_what_the_parsers_found_is_reported_as_a_fact(settings: Settings) -> None:
    handler, seen = _answering({"result": {"verdict": "deny", "reason_code": "sql_not_read_only"}})

    decision = _engine(settings, handler).action_verdict(
        _action(arguments={"query": "DELETE FROM orders"}), frozenset({Role.CALLER})
    )

    assert decision == (Verdict.DENY, "sql_not_read_only")
    assert json.loads(seen[0].content)["input"]["facts"] == {
        "argument_violation": "sql_not_read_only"
    }


@pytest.mark.parametrize("verdict", ["allow", "require_approval"])
def test_a_bundle_cannot_authorize_arguments_the_gateway_found_unsafe(
    settings: Settings, verdict: str
) -> None:
    handler, _ = _answering({"result": {"verdict": verdict, "reason_code": "custom_rule"}})

    decision = _engine(settings, handler).action_verdict(
        _action(arguments={"query": "DROP TABLE orders"}), frozenset({Role.CALLER})
    )

    assert decision == (Verdict.DENY, "sql_not_read_only")


def test_a_bundle_may_deny_what_the_built_in_policy_would_allow(settings: Settings) -> None:
    handler, _ = _answering(
        {"result": {"verdict": "deny", "reason_code": "outside_business_hours"}}
    )

    decision = _engine(settings, handler).action_verdict(_action(), frozenset({Role.CALLER}))

    assert decision == (Verdict.DENY, "outside_business_hours")


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"result": None},
        {"result": "allow"},
        {"result": {"verdict": "allow"}},
        {"result": {"reason_code": "policy_allow"}},
        {"result": {"verdict": "permit", "reason_code": "policy_allow"}},
        {"result": {"verdict": "allow", "reason_code": 7}},
        {"result": {"verdict": "allow", "reason_code": "Not A Reason Code"}},
        {"result": {"verdict": "allow", "reason_code": ""}},
        ["allow"],
    ],
)
def test_an_undefined_or_malformed_decision_is_unavailability(
    settings: Settings, body: Any
) -> None:
    handler, _ = _answering(body)
    engine = _engine(settings, handler)

    with pytest.raises(PolicyEngineUnavailableError):
        _content(engine)
    with pytest.raises(PolicyEngineUnavailableError):
        engine.action_verdict(_action(), frozenset({Role.CALLER}))


def test_a_verdict_that_does_not_belong_to_the_enforcement_point_is_refused(
    settings: Settings,
) -> None:
    approval, _ = _answering({"result": {"verdict": "require_approval", "reason_code": "held"}})
    transform, _ = _answering({"result": {"verdict": "transform", "reason_code": "redacted"}})

    with pytest.raises(PolicyEngineUnavailableError):
        _content(_engine(settings, approval))
    with pytest.raises(PolicyEngineUnavailableError):
        _engine(settings, transform).action_verdict(_action(), frozenset({Role.CALLER}))


@pytest.mark.parametrize("status", [404, 500, 503])
def test_an_error_response_is_unavailability(settings: Settings, status: int) -> None:
    handler, _ = _answering(ALLOW, status)

    with pytest.raises(PolicyEngineUnavailableError):
        _content(_engine(settings, handler))


def test_a_response_that_is_not_json_is_unavailability(settings: Settings) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>proxy error</html>")

    with pytest.raises(PolicyEngineUnavailableError):
        _content(_engine(settings, handler))


@pytest.mark.parametrize("failure", [httpx.ConnectError, httpx.ReadTimeout])
def test_no_answer_is_unavailability(settings: Settings, failure: type[Exception]) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise failure("opa unreachable")

    engine = _engine(settings, handler)

    with pytest.raises(PolicyEngineUnavailableError):
        _content(engine)
    assert not engine.available()
    assert not policy_available(engine)


def test_availability_follows_the_health_endpoint(settings: Settings) -> None:
    healthy, seen = _answering({})
    unhealthy, _ = _answering({}, 500)

    assert _engine(settings, healthy).available()
    assert seen[0].url.path == "/health"
    assert not _engine(settings, unhealthy).available()


def test_an_engine_that_cannot_report_availability_is_assumed_available() -> None:
    class Bare:
        pass

    assert policy_available(Bare())  # type: ignore[arg-type]


def test_the_engine_needs_a_url(settings: Settings) -> None:
    with pytest.raises(ValueError, match="opa_url"):
        OpaPolicyEngine(settings)


def test_the_default_client_uses_the_configured_url_and_timeout(settings: Settings) -> None:
    configured = settings.model_copy(
        update={"opa_url": "http://opa.internal:8181", "opa_timeout_seconds": 0.25}
    )

    engine = OpaPolicyEngine(configured)

    assert str(engine._client.base_url) == "http://opa.internal:8181"
    assert engine._client.timeout == httpx.Timeout(0.25)
    engine.close()
    assert engine._client.is_closed


def test_the_bundle_data_is_the_gateways_own_tool_registry() -> None:
    committed = json.loads((BUNDLE / "guardrail" / "data.json").read_text(encoding="utf-8"))

    assert committed == tool_registry_data()
    assert committed["approval_effects"] == ["destructive", "external", "write"]


def test_the_bundle_revision_is_the_default_policy_version() -> None:
    manifest = json.loads((BUNDLE / ".manifest").read_text(encoding="utf-8"))

    assert manifest == {"revision": Settings().policy_version, "roots": ["guardrail"]}
