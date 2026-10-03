"""Section 10: entity rules, pseudonymization, canaries, and the Presidio adapter."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from guardrail_gateway.app import create_app
from guardrail_gateway.audit import InMemoryTransport
from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import DeterministicInspector
from guardrail_gateway.identity import Role, issue_token
from guardrail_gateway.models import EntityAction
from guardrail_gateway.presidio import PresidioInspector

pytestmark = pytest.mark.integration

TRACE = "33333333-3333-4333-8333-333333333333"
OTHER_TRACE = "44444444-4444-4444-8444-444444444444"
CANARY = "canary-7f3a9c2e1b5d"
TICKET = "Customer casey@example.com (backup casey@example.com) called from +1 (212) 555-0100."


def _body(content: str, **fields: Any) -> dict[str, Any]:
    return {"identity": "user-1", "tenant_id": "acme", "content": content, **fields}


@contextmanager
def _gateway(settings: Settings, **overrides: Any) -> Iterator[TestClient]:
    adapters = {
        key: overrides.pop(key)
        for key in list(overrides)
        if key in {"inspectors", "audit_transport"}
    }
    with TestClient(create_app(settings.model_copy(update=overrides), **adapters)) as client:
        yield client


def _pseudonymizing(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "sensitive_entity_actions": {
                "pii_email": EntityAction.PSEUDONYMIZE,
                "pii_phone": EntityAction.PSEUDONYMIZE,
            }
        }
    )


def test_pii_is_pseudonymized_consistently(settings: Settings, caller_auth: dict[str, str]) -> None:
    with _gateway(_pseudonymizing(settings)) as client:
        body = client.post(
            "/v1/inspect/input", headers=caller_auth, json=_body(TICKET, trace_id=TRACE)
        ).json()

    assert (body["verdict"], body["reason_code"]) == (
        "transform",
        "sensitive_content_pseudonymized",
    )
    assert body["transformed_content"] == (
        "Customer [EMAIL_1] (backup [EMAIL_1]) called from [PHONE_1]."
    )
    assert "casey@example.com" not in str(body)


def test_pseudonyms_are_restored_for_the_same_tenant_and_trace(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(_pseudonymizing(settings)) as client:
        client.post("/v1/inspect/input", headers=caller_auth, json=_body(TICKET, trace_id=TRACE))
        restored = client.post(
            "/v1/pseudonyms/restore",
            headers=caller_auth,
            json=_body("I emailed [EMAIL_1] and rang [PHONE_1].", trace_id=TRACE),
        ).json()

    assert restored == {
        "content": "I emailed casey@example.com and rang +1 (212) 555-0100.",
        "restored": 2,
    }


def test_pseudonymized_model_output_is_not_a_leak(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(_pseudonymizing(settings)) as client:
        body = client.post(
            "/v1/inspect/output", headers=caller_auth, json=_body("I have emailed [EMAIL_1].")
        ).json()

    assert body["verdict"] == "allow"


def test_another_trace_cannot_restore_the_pseudonyms(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(_pseudonymizing(settings)) as client:
        client.post("/v1/inspect/input", headers=caller_auth, json=_body(TICKET, trace_id=TRACE))
        restored = client.post(
            "/v1/pseudonyms/restore",
            headers=caller_auth,
            json=_body("Reply to [EMAIL_1].", trace_id=OTHER_TRACE),
        ).json()

    assert restored == {"content": "Reply to [EMAIL_1].", "restored": 0}


def test_another_tenant_cannot_restore_the_pseudonyms(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    intruder = issue_token(settings, "user-1", "contoso", roles=(Role.CALLER,))

    with _gateway(_pseudonymizing(settings)) as client:
        client.post("/v1/inspect/input", headers=caller_auth, json=_body(TICKET, trace_id=TRACE))
        own_tenant = client.post(
            "/v1/pseudonyms/restore",
            headers={"Authorization": f"Bearer {intruder}"},
            json={**_body("Reply to [EMAIL_1].", trace_id=TRACE), "tenant_id": "contoso"},
        ).json()
        spoofed = client.post(
            "/v1/pseudonyms/restore",
            headers={"Authorization": f"Bearer {intruder}"},
            json=_body("Reply to [EMAIL_1].", trace_id=TRACE),
        )

    assert own_tenant["restored"] == 0
    assert spoofed.status_code == 403


def test_restoring_requires_a_credential(client: TestClient) -> None:
    response = client.post("/v1/pseudonyms/restore", json=_body("[EMAIL_1]", trace_id=TRACE))

    assert response.status_code == 401


def test_restoration_is_audited_without_the_values(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    transport = InMemoryTransport(100)

    with _gateway(_pseudonymizing(settings), audit_transport=transport) as client:
        client.post("/v1/inspect/input", headers=caller_auth, json=_body(TICKET, trace_id=TRACE))
        client.post(
            "/v1/pseudonyms/restore", headers=caller_auth, json=_body("[EMAIL_1]", trace_id=TRACE)
        )

    events = transport.snapshot()
    assert events[-1] == {
        "enforcement_point": "operation",
        "verdict": "allow",
        "reason_code": "pseudonyms_restored",
        "tenant_id": "acme",
        "trace_id": TRACE,
        "count": 1,
    }
    assert "casey@example.com" not in str(events)


def test_a_tenant_may_deny_a_category_outright(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    rules = {"tenant_entity_actions": {"acme": {"pii_phone": EntityAction.DENY}}}

    with _gateway(settings, **rules) as client:
        body = client.post("/v1/inspect/input", headers=caller_auth, json=_body(TICKET)).json()

    assert (body["verdict"], body["reason_code"]) == ("deny", "sensitive_content_denied")
    assert body["transformed_content"] is None


def test_a_tenant_may_allow_a_category_through(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    rules = {
        "tenant_entity_actions": {
            "acme": {"pii_email": EntityAction.ALLOW, "pii_phone": EntityAction.ALLOW}
        }
    }

    with _gateway(settings, **rules) as client:
        body = client.post("/v1/inspect/input", headers=caller_auth, json=_body(TICKET)).json()

    assert (body["verdict"], body["reason_code"]) == ("allow", "policy_allow")


def test_mixed_rules_are_applied_per_category(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    rules = {
        "sensitive_entity_actions": {
            "pii_email": EntityAction.PSEUDONYMIZE,
            "pii_phone": EntityAction.ALLOW,
        }
    }

    with _gateway(settings, **rules) as client:
        body = client.post(
            "/v1/inspect/input",
            headers=caller_auth,
            json=_body(TICKET + " Key sk_abcdefghijklmnop1234.", trace_id=TRACE),
        ).json()

    assert body["reason_code"] == "sensitive_content_redacted"
    assert body["transformed_content"] == (
        "Customer [EMAIL_1] (backup [EMAIL_1]) called from +1 (212) 555-0100. "
        "Key [REDACTED_SECRET]."
    )


@pytest.mark.parametrize("path", ["input", "context", "output"])
def test_a_canary_is_denied_at_every_enforcement_point(
    settings: Settings, caller_auth: dict[str, str], path: str
) -> None:
    with _gateway(settings, canary_secrets=(SecretStr(CANARY),)) as client:
        body = client.post(
            f"/v1/inspect/{path}",
            headers=caller_auth,
            json=_body(f"config dump token={CANARY}", trust_level="trusted"),
        ).json()

    assert (body["verdict"], body["reason_code"]) == ("deny", "canary_leak_detected")
    assert CANARY not in str(body)


def test_an_encoded_canary_is_still_a_leak(settings: Settings, caller_auth: dict[str, str]) -> None:
    encoded = base64.b64encode(f"token={CANARY}".encode()).decode()

    with _gateway(settings, canary_secrets=(SecretStr(CANARY),)) as client:
        body = client.post(
            "/v1/inspect/output", headers=caller_auth, json=_body(f"Here you go: {encoded}")
        ).json()

    assert body["reason_code"] == "canary_leak_detected"


def test_a_canary_leak_is_visible_in_the_audit_trail(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    transport = InMemoryTransport(100)

    with _gateway(
        settings, canary_secrets=(SecretStr(CANARY),), audit_transport=transport
    ) as client:
        client.post("/v1/inspect/output", headers=caller_auth, json=_body(f"key {CANARY}"))

    event = transport.snapshot()[-1]
    assert event["reason_code"] == "canary_leak_detected"
    assert event["evidence_categories"] == ["canary"]


def _presidio(handler: Any) -> PresidioInspector:
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://presidio.test")
    return PresidioInspector("http://presidio.test", client=client)


def test_entities_only_presidio_recognizes_are_redacted(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    content = "Casey Jones asked about a refund."
    presidio = _presidio(
        lambda request: httpx.Response(
            200, json=[{"entity_type": "PERSON", "start": 0, "end": 11, "score": 0.9}]
        )
    )

    with _gateway(settings, inspectors=(DeterministicInspector(), presidio)) as client:
        body = client.post("/v1/inspect/input", headers=caller_auth, json=_body(content)).json()

    assert body["verdict"] == "transform"
    assert body["transformed_content"] == "[REDACTED_PERSON] asked about a refund."


def test_an_unreachable_presidio_blocks_content(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    presidio = _presidio(lambda request: httpx.Response(503))

    with _gateway(settings, inspectors=(DeterministicInspector(), presidio)) as client:
        body = client.post("/v1/inspect/input", headers=caller_auth, json=_body("hello")).json()

    assert (body["verdict"], body["reason_code"]) == ("deny", "content_inspection_unavailable")


def test_presidio_is_wired_in_when_a_url_is_configured(settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"presidio_url": "http://presidio.internal:3000"}))

    kinds = [type(inspector).__name__ for inspector in app.state.gateway_service.inspectors]

    assert kinds == ["DeterministicInspector", "PresidioInspector"]
