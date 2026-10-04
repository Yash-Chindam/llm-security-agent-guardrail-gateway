"""Unit tests for audit delivery, buffering, and durability blocking."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from guardrail_gateway.audit import AuditSink, InMemoryTransport, TransportUnavailableError
from guardrail_gateway.models import DetectorEvidence, EnforcementPoint, SecurityDecision, Verdict

pytestmark = pytest.mark.unit

# Added to every event on publication.
_ENVELOPE = ("event_id", "schema_version", "occurred_at")


class FlakyTransport:
    """A transport whose availability the test controls."""

    def __init__(self) -> None:
        self.available = True
        self.events: list[dict[str, Any]] = []

    def send(self, event: dict[str, Any]) -> None:
        if not self.available:
            raise TransportUnavailableError
        self.events.append(event)


def _decision(reason: str = "policy_allow") -> SecurityDecision:
    return SecurityDecision(
        request_id=uuid4(),
        trace_id=uuid4(),
        enforcement_point=EnforcementPoint.INPUT,
        tenant_id="acme",
        policy_version="v1",
        verdict=Verdict.ALLOW,
        reason_code=reason,
        evidence=[
            DetectorEvidence(
                detector="d",
                version="1",
                category="pii_email",
                score=0.9,
                threshold=0.8,
                redacted_excerpt="contact [MATCH] today",
                explanation="An email address was detected.",
            )
        ],
        latency_ms=1.0,
    )


def test_an_event_carries_categories_but_never_the_excerpt() -> None:
    transport = InMemoryTransport(10)
    sink = AuditSink(10, transport)

    sink.publish(_decision())

    event = transport.snapshot()[0]
    assert event["evidence_categories"] == ["pii_email"]
    assert "[MATCH]" not in str(event)


def test_the_default_transport_keeps_the_sink_durable() -> None:
    sink = AuditSink(10)

    sink.publish(_decision())

    assert sink.state() == "durable"
    assert sink.pending == 0
    assert sink.accepting()


def test_events_are_buffered_while_the_transport_is_down() -> None:
    transport = FlakyTransport()
    sink = AuditSink(10, transport)
    transport.available = False

    sink.publish(_decision())

    assert sink.pending == 1
    assert sink.state() == "buffering"
    assert sink.accepting()


def test_buffered_events_are_delivered_in_order_on_recovery() -> None:
    transport = FlakyTransport()
    sink = AuditSink(10, transport)
    transport.available = False
    sink.publish(_decision("first"))
    sink.publish(_decision("second"))

    transport.available = True
    sink.publish(_decision("third"))

    assert [event["reason_code"] for event in transport.events] == ["first", "second", "third"]
    assert sink.pending == 0


def test_a_new_event_never_overtakes_the_buffer() -> None:
    """A transport that recovers mid-publish must not reorder the trail."""

    class RecoversAfterFirstRefusal(FlakyTransport):
        def __init__(self) -> None:
            super().__init__()
            self.refusals = 0

        def send(self, event: dict[str, Any]) -> None:
            if self.refusals < 2:
                self.refusals += 1
                raise TransportUnavailableError
            self.events.append(event)

    transport = RecoversAfterFirstRefusal()
    sink = AuditSink(10, transport)
    sink.publish(_decision("first"))  # refused, buffered
    sink.publish(_decision("second"))  # flush refused, so it queues behind "first"

    sink.publish(_decision("third"))

    assert [event["reason_code"] for event in transport.events] == ["first", "second", "third"]


def test_mandatory_audit_stops_accepting_once_the_buffer_is_full() -> None:
    transport = FlakyTransport()
    sink = AuditSink(10, transport, mandatory=True)
    transport.available = False
    for _ in range(10):
        sink.publish(_decision())

    assert not sink.accepting()
    assert sink.state() == "blocked"

    sink.publish(_decision())
    assert sink.dropped == 1
    assert sink.pending == 10


def test_mandatory_audit_accepts_again_when_the_transport_recovers() -> None:
    transport = FlakyTransport()
    sink = AuditSink(10, transport, mandatory=True)
    transport.available = False
    for _ in range(10):
        sink.publish(_decision())

    transport.available = True

    assert sink.accepting()
    assert sink.state() == "durable"
    assert len(transport.events) == 10


def test_best_effort_analytics_keeps_accepting_and_counts_what_it_drops() -> None:
    transport = FlakyTransport()
    sink = AuditSink(10, transport, mandatory=False)
    transport.available = False
    for _ in range(13):
        sink.publish(_decision())

    assert sink.accepting()
    assert sink.state() == "buffering"
    assert sink.pending == 10
    assert sink.dropped == 3


def test_a_credential_rejection_is_recorded_without_the_credential() -> None:
    transport = InMemoryTransport(10)
    sink = AuditSink(10, transport)

    sink.publish_rejection("credentials_invalid", "/v1/inspect/input")

    [event] = transport.snapshot()
    assert {key: event.pop(key) is not None for key in _ENVELOPE} == dict.fromkeys(_ENVELOPE, True)
    assert event == {
        "enforcement_point": "credential",
        "verdict": "deny",
        "reason_code": "credentials_invalid",
        "path": "/v1/inspect/input",
    }
