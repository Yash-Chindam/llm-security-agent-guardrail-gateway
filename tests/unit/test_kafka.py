"""Unit tests for the Kafka audit transport, driven without a broker."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from guardrail_gateway.audit import AuditSink, TransportUnavailableError
from guardrail_gateway.config import Settings
from guardrail_gateway.kafka import KafkaTransport, producer_factory
from guardrail_gateway.models import EnforcementPoint, SecurityDecision, Verdict

pytestmark = pytest.mark.unit

TOPIC = "guardrail.security-events"


class FakeFuture:
    """Resolved before it is returned, as a fast broker's reply would be."""

    def __init__(self, error: str | None) -> None:
        self._error = error

    def add_callback(self, callback: Callable[[Any], Any]) -> FakeFuture:
        if self._error is None:
            callback(object())
        return self

    def add_errback(self, errback: Callable[[Any], Any]) -> FakeFuture:
        if self._error is not None:
            errback(self._error)
        return self


class FakeProducer:
    def __init__(self, **config: Any) -> None:
        self.config = config
        self.queue_full = False
        self.broker_refuses = False
        self.flush_times_out = False
        self.delivered: list[tuple[str, bytes, bytes | None]] = []

    def send(self, topic: str, value: bytes, key: bytes | None) -> FakeFuture:
        if self.queue_full:
            raise TimeoutError("no room in the send buffer")
        if self.broker_refuses:
            return FakeFuture("not enough replicas")
        self.delivered.append((topic, value, key))
        return FakeFuture(None)

    def flush(self, timeout: float) -> None:
        if self.flush_times_out:
            raise TimeoutError

    def payloads(self) -> list[dict[str, Any]]:
        return [json.loads(value) for _, value, _ in self.delivered]


def _transport(producer: FakeProducer) -> KafkaTransport:
    return KafkaTransport(lambda: producer, TOPIC)


def _decision(reason: str = "policy_allow") -> SecurityDecision:
    return SecurityDecision(
        request_id=uuid4(),
        trace_id=uuid4(),
        enforcement_point=EnforcementPoint.INPUT,
        tenant_id="acme",
        policy_version="v1",
        verdict=Verdict.ALLOW,
        reason_code=reason,
        latency_ms=1.0,
    )


def test_an_event_is_published_as_json_keyed_by_tenant() -> None:
    producer = FakeProducer()
    transport = _transport(producer)

    transport.send({"tenant_id": "acme", "reason_code": "policy_allow"})

    assert producer.delivered == [
        (TOPIC, b'{"reason_code":"policy_allow","tenant_id":"acme"}', b"acme")
    ]
    assert transport.in_flight == 0


def test_an_event_without_a_tenant_has_no_key() -> None:
    producer = FakeProducer()

    _transport(producer).send({"reason_code": "missing_credential"})

    assert producer.delivered[0][2] is None


def test_a_full_send_buffer_is_reported_as_unavailable() -> None:
    producer = FakeProducer()
    producer.queue_full = True
    transport = _transport(producer)

    with pytest.raises(TransportUnavailableError):
        transport.send({"tenant_id": "acme"})

    assert transport.in_flight == 0


def test_a_broker_that_is_down_at_first_use_is_retried_on_the_next_send() -> None:
    producer = FakeProducer()
    attempts: list[int] = []

    def connect() -> FakeProducer:
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("no brokers available")
        return producer

    now = [0.0]
    transport = KafkaTransport(connect, TOPIC, clock=lambda: now[0])

    with pytest.raises(TransportUnavailableError):
        transport.send({"tenant_id": "acme", "n": 1})
    # Connecting waits on the brokers, so it is not attempted again at once:
    # an outage must not add that wait to every request.
    with pytest.raises(TransportUnavailableError):
        transport.send({"tenant_id": "acme", "n": 1})
    assert len(attempts) == 1

    now[0] = 5.0
    transport.send({"tenant_id": "acme", "n": 2})
    transport.send({"tenant_id": "acme", "n": 3})

    # Connected once it could, and not again afterwards.
    assert len(attempts) == 2
    assert [payload["n"] for payload in producer.payloads()] == [2, 3]


def test_an_event_the_broker_refuses_is_resent_before_anything_newer() -> None:
    producer = FakeProducer()
    transport = _transport(producer)
    producer.broker_refuses = True

    transport.send({"tenant_id": "acme", "n": 1})

    assert producer.delivered == []
    assert transport.delivery_failures == 1
    assert transport.in_flight == 1

    producer.broker_refuses = False
    transport.send({"tenant_id": "acme", "n": 2})

    assert [payload["n"] for payload in producer.payloads()] == [1, 2]
    assert transport.in_flight == 0


def test_a_broker_that_keeps_refusing_does_not_loop_or_lose_events() -> None:
    producer = FakeProducer()
    transport = _transport(producer)
    producer.broker_refuses = True

    transport.send({"tenant_id": "acme", "n": 1})
    transport.send({"tenant_id": "acme", "n": 2})
    transport.send({"tenant_id": "acme", "n": 3})

    assert transport.in_flight == 3
    producer.broker_refuses = False
    transport.send({"tenant_id": "acme", "n": 4})

    assert [payload["n"] for payload in producer.payloads()] == [1, 2, 3, 4]
    assert transport.in_flight == 0


def test_refused_events_keep_their_order_when_the_retry_cannot_be_queued() -> None:
    producer = FakeProducer()
    transport = _transport(producer)
    producer.broker_refuses = True
    transport.send({"tenant_id": "acme", "n": 1})
    transport.send({"tenant_id": "acme", "n": 2})
    producer.queue_full = True

    with pytest.raises(TransportUnavailableError):
        transport.send({"tenant_id": "acme", "n": 3})

    producer.queue_full = False
    producer.broker_refuses = False
    transport.send({"tenant_id": "acme", "n": 3})

    assert [payload["n"] for payload in producer.payloads()] == [1, 2, 3]


def test_closing_flushes_and_reports_what_was_left() -> None:
    producer = FakeProducer()
    transport = _transport(producer)
    producer.broker_refuses = True
    transport.send({"tenant_id": "acme"})
    producer.flush_times_out = True

    assert transport.close() == 1


def test_closing_a_transport_that_never_connected_reports_nothing_left() -> None:
    assert _transport(FakeProducer()).close() == 0


def test_the_audit_sink_buffers_through_a_kafka_outage_in_order() -> None:
    producer = FakeProducer()
    sink = AuditSink(10, _transport(producer))
    producer.queue_full = True

    sink.publish(_decision("first"))
    sink.publish(_decision("second"))

    assert sink.pending == 2
    assert sink.state() == "buffering"

    producer.queue_full = False
    sink.publish(_decision("third"))

    assert [payload["reason_code"] for payload in producer.payloads()] == [
        "first",
        "second",
        "third",
    ]
    assert sink.state() == "durable"
    assert sink.in_flight == 0


def test_the_sink_reports_events_the_broker_has_not_acknowledged() -> None:
    producer = FakeProducer()
    sink = AuditSink(10, _transport(producer))
    producer.broker_refuses = True

    sink.publish(_decision())

    assert sink.in_flight == 1


def test_the_producer_is_idempotent_and_waits_for_every_replica(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "kafka", SimpleNamespace(KafkaProducer=FakeProducer))
    configured = settings.model_copy(
        update={
            "kafka_bootstrap_servers": "kafka:9092",
            # A deployment cannot weaken the durability settings through the
            # pass-through client configuration.
            "kafka_client_config": {"security_protocol": "SSL", "acks": 0},
        }
    )

    producer = producer_factory(configured)()

    assert isinstance(producer, FakeProducer)
    assert producer.config == {
        "max_block_ms": 250,
        "bootstrap_servers": "kafka:9092",
        "security_protocol": "SSL",
        "acks": "all",
        "enable_idempotence": True,
    }


def test_the_configuration_and_calls_match_the_real_client() -> None:
    kafka = pytest.importorskip("kafka")
    import inspect

    send = list(inspect.signature(kafka.KafkaProducer.send).parameters)
    flush = list(inspect.signature(kafka.KafkaProducer.flush).parameters)

    assert send[:4] == ["self", "topic", "value", "key"]
    assert flush == ["self", "timeout"]
    for option in ("max_block_ms", "bootstrap_servers", "acks", "enable_idempotence"):
        assert option in kafka.KafkaProducer.DEFAULT_CONFIG


def test_a_missing_client_library_is_a_clear_configuration_error(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "kafka", None)

    with pytest.raises(RuntimeError, match="'kafka' extra"):
        producer_factory(settings.model_copy(update={"kafka_bootstrap_servers": "kafka:9092"}))
