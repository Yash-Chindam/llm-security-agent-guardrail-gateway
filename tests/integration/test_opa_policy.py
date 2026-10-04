"""The OPA policy engine behind the HTTP API.

The wiring and failure tests run everywhere against a stand-in. The parity
tests need a real OPA server loaded with `deploy/opa/policy`, and run when
`GUARDRAIL_TEST_OPA_URL` names one, which CI does. They are what shows the
Rego bundle decides exactly as the built-in policy does.
"""

from __future__ import annotations

import itertools
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from guardrail_gateway.app import create_app
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
)
from guardrail_gateway.opa import OpaPolicyEngine
from guardrail_gateway.policy import LocalPolicyEngine
from guardrail_gateway.redteam.credentials import build_credentials
from guardrail_gateway.redteam.runner import Baseline, evaluate_gate, run_suite
from guardrail_gateway.tools import TOOLS

pytestmark = pytest.mark.integration

OPA_URL = os.environ.get("GUARDRAIL_TEST_OPA_URL")
needs_opa = pytest.mark.skipif(OPA_URL is None, reason="GUARDRAIL_TEST_OPA_URL is not set")
BASELINE_PATH = Path("src/guardrail_gateway/redteam/baseline.json")

CONTENT = {"identity": "user-1", "tenant_id": "acme", "content": "What is our refund policy?"}
WRITE = {
    "identity": "user-1",
    "tenant_id": "acme",
    "tool": "update_record",
    "resource": "tenant:acme:orders",
    "arguments": {"record_id": "1"},
    "side_effect": "write",
}


def _opa_stub(handler: Any) -> httpx.Client:
    return httpx.Client(base_url="http://opa:8181", transport=httpx.MockTransport(handler))


def _with_opa(settings: Settings, handler: Any) -> TestClient:
    configured = settings.model_copy(update={"opa_url": "http://opa:8181"})
    return TestClient(
        create_app(configured, policy=OpaPolicyEngine(configured, _opa_stub(handler)))
    )


def _down(_request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("opa unreachable")


def test_configuring_a_url_makes_opa_the_decision_point(settings: Settings) -> None:
    configured = settings.model_copy(update={"opa_url": "http://opa.internal:8181"})

    with TestClient(create_app(configured)) as client:
        engine = client.app.state.gateway_service.policy  # type: ignore[attr-defined]

        assert isinstance(engine, OpaPolicyEngine)
    assert engine._client.is_closed


def test_opas_decision_is_the_gateways_decision(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={})
        return httpx.Response(
            200, json={"result": {"verdict": "deny", "reason_code": "outside_business_hours"}}
        )

    with _with_opa(settings, handler) as client:
        content = client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT).json()
        action = client.post("/v1/inspect/action", headers=caller_auth, json=WRITE).json()
        ready = client.get("/health/ready")

    assert (content["verdict"], content["reason_code"]) == ("deny", "outside_business_hours")
    assert (action["verdict"], action["reason_code"]) == ("deny", "outside_business_hours")
    assert ready.status_code == 200
    assert ready.json()["policy"] == "available"


def test_an_unreachable_opa_fails_closed_and_takes_the_replica_out_of_rotation(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _with_opa(settings, _down) as client:
        content = client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT).json()
        action = client.post("/v1/inspect/action", headers=caller_auth, json=WRITE).json()
        ready = client.get("/health/ready")

    assert (content["verdict"], content["reason_code"]) == ("deny", "policy_engine_unavailable")
    assert (action["verdict"], action["reason_code"]) == ("deny", "policy_engine_unavailable")
    assert action["approval_id"] is None
    assert ready.status_code == 503
    assert ready.json()["policy"] == "unavailable"


def test_an_undefined_decision_is_not_an_allow(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        # What OPA returns when no rule produced a decision.
        return httpx.Response(200, json={})

    with _with_opa(settings, handler) as client:
        content = client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT).json()

    assert (content["verdict"], content["reason_code"]) == ("deny", "policy_engine_unavailable")


def test_restricted_mode_still_never_authorizes_a_side_effect_without_opa(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    restricted = settings.model_copy(update={"restricted_read_only_mode": True})

    with _with_opa(restricted, _down) as client:
        content = client.post("/v1/inspect/input", headers=caller_auth, json=CONTENT).json()
        action = client.post("/v1/inspect/action", headers=caller_auth, json=WRITE).json()

    assert (content["verdict"], content["reason_code"]) == ("allow", "restricted_read_only_mode")
    assert (action["verdict"], action["reason_code"]) == ("deny", "policy_engine_unavailable")


# ---- parity with the built-in policy, against a real OPA server

_CATEGORIES = [
    "canary",
    "embedded_action",
    "prompt_injection",
    "jailbreak",
    "secret",
    "pii_email",
    "pii_phone",
    "unknown_category",
]
_ENTITY_RULES: list[dict[str, EntityAction]] = [
    {},
    {"pii_email": EntityAction.ALLOW},
    {"pii_email": EntityAction.PSEUDONYMIZE},
    {"pii_email": EntityAction.PSEUDONYMIZE, "pii_phone": EntityAction.PSEUDONYMIZE},
    {"pii_phone": EntityAction.DENY},
    {"secret": EntityAction.DENY, "pii_email": EntityAction.ALLOW},
]


def _evidence(category: str, obfuscated: bool = False) -> DetectorEvidence:
    return DetectorEvidence(
        detector=DECODED_DETECTOR if obfuscated else "deterministic",
        version="1",
        category=category,
        score=0.9,
        threshold=0.8,
        redacted_excerpt="[MATCH]",
        explanation="Detected.",
    )


def _evidence_sets() -> list[list[DetectorEvidence]]:
    singles = [[_evidence(category)] for category in _CATEGORIES]
    pairs = [
        [_evidence(first), _evidence(second)]
        for first, second in itertools.combinations(_CATEGORIES, 2)
    ]
    return [[], [_evidence("pii_email", obfuscated=True)], *singles, *pairs]


@needs_opa
def test_the_bundle_decides_content_exactly_as_the_built_in_policy_does(
    settings: Settings,
) -> None:
    assert OPA_URL is not None
    compared = 0
    for rules in _ENTITY_RULES:
        configured = settings.model_copy(
            update={"opa_url": OPA_URL, "sensitive_entity_actions": rules}
        )
        local, opa = LocalPolicyEngine(configured), OpaPolicyEngine(configured)
        for point, trust, source, evidence in itertools.product(
            (EnforcementPoint.INPUT, EnforcementPoint.CONTEXT, EnforcementPoint.OUTPUT),
            TrustLevel,
            (None, "acme", "other"),
            _evidence_sets(),
        ):
            arguments = (point, trust, source, "acme", evidence)
            assert opa.content_verdict(*arguments) == local.content_verdict(*arguments), (
                rules,
                point,
                trust,
                source,
                [item.category for item in evidence],
            )
            compared += 1
        opa.close()
    assert compared > 3_000


_ARGUMENTS: dict[str, list[dict[str, Any]]] = {
    "search_documents": [{"q": "refund"}, {"q": ""}, {"unexpected": True}],
    "execute_sql": [
        {"query": "SELECT 1"},
        {"query": "DELETE FROM orders"},
        {"query": "SELECT 1; DROP TABLE orders"},
        {},
    ],
    "read_file": [{"path": "workspace/notes.txt"}, {"path": "../etc/passwd"}, {"path": ""}],
    "send_email": [
        {"to": "a@example.com", "subject": "Hi", "body": "Hello"},
        {"to": "not-an-address", "subject": "Hi", "body": "Hello"},
    ],
    "fetch_url": [
        {"url": "https://api.partner.test/v1/items"},
        {"url": "https://evil.example/steal"},
        {"url": "http://169.254.169.254/latest/meta-data"},
    ],
    "update_record": [{"record_id": "1"}, {"record_id": "1; DROP"}],
    "delete_record": [{"record_id": "9"}, {}],
    "run_code": [
        {"language": "python", "code": "print(1)"},
        {"language": "python", "code": "print(1)", "network": True},
        {"language": "bash", "code": "id"},
    ],
    "run_shell": [{"command": "id"}],
}
_ROLE_SETS = [
    frozenset[Role](),
    frozenset({Role.CALLER}),
    frozenset({Role.OPERATOR}),
    frozenset({Role.CALLER, Role.OPERATOR}),
    frozenset({Role.REVIEWER, Role.AUDITOR}),
]


@needs_opa
def test_the_bundle_decides_actions_exactly_as_the_built_in_policy_does(
    settings: Settings,
) -> None:
    assert OPA_URL is not None
    assert set(TOOLS) < set(_ARGUMENTS)
    configured = settings.model_copy(update={"opa_url": OPA_URL})
    local, opa = LocalPolicyEngine(configured), OpaPolicyEngine(configured)
    compared = 0
    for tool, argument_sets in _ARGUMENTS.items():
        for arguments, effect, resource, roles in itertools.product(
            argument_sets,
            SideEffect,
            ("tenant:acme:orders", "tenant:other:orders", "tenant:acme-evil:orders", "orders"),
            _ROLE_SETS,
        ):
            request = ActionInspectionRequest(
                identity="user-1",
                tenant_id="acme",
                tool=tool,
                resource=resource,
                arguments=arguments,
                side_effect=effect,
            )
            assert opa.action_verdict(request, roles) == local.action_verdict(request, roles), (
                tool,
                arguments,
                effect,
                resource,
                sorted(roles),
            )
            compared += 1
    opa.close()
    assert compared > 1_500


class _InProcess:
    def __init__(self, client: TestClient) -> None:
        self._client = client

    def post(
        self, path: str, payload: dict[str, Any], headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, Any]]:
        response = self._client.post(path, json=payload, headers=headers)
        body = response.json()
        return response.status_code, body if isinstance(body, dict) else {}


@needs_opa
def test_the_adversarial_suite_meets_its_baseline_with_opa_deciding(settings: Settings) -> None:
    configured = settings.model_copy(update={"opa_url": OPA_URL})
    baseline = Baseline.model_validate_json(BASELINE_PATH.read_text(encoding="utf-8"))

    with TestClient(create_app(configured)) as client:
        assert isinstance(client.app.state.gateway_service.policy, OpaPolicyEngine)  # type: ignore[attr-defined]
        run = run_suite(_InProcess(client), "opa", "test-policy", build_credentials(configured))

    failed = [result.scenario_id for result in run.results if not result.passed]
    assert failed == []
    assert evaluate_gate(run, baseline).passed
