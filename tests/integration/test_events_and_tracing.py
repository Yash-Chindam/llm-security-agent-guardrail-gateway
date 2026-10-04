"""Kafka wiring, detector latency, and decision traces through the HTTP API."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from guardrail_gateway.app import create_app
from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import DetectorUnavailableError, Finding
from guardrail_gateway.tracing import build_provider

pytestmark = pytest.mark.integration

TRACE = "66666666-6666-4666-8666-666666666666"
SECRET_EMAIL = "pat.doe@example.com"
BENIGN = {"identity": "user-1", "tenant_id": "acme", "trace_id": TRACE, "content": "Hello"}
SENSITIVE = {**BENIGN, "content": f"Reach me at {SECRET_EMAIL} please."}
ACTION = {
    "identity": "user-1",
    "tenant_id": "acme",
    "trace_id": TRACE,
    "tool": "delete_record",
    "resource": "tenant:acme:orders",
    "arguments": {"record_id": "9"},
    "side_effect": "destructive",
}


class Acknowledged:
    def add_callback(self, callback: Any) -> Acknowledged:
        callback(object())
        return self

    def add_errback(self, errback: Any) -> Acknowledged:
        return self


class RecordingProducer:
    def __init__(self, **config: Any) -> None:
        self.config = config
        self.messages: list[tuple[str, bytes, bytes | None]] = []
        self.flushed = False

    def send(self, topic: str, value: bytes, key: bytes | None) -> Acknowledged:
        self.messages.append((topic, value, key))
        return Acknowledged()

    def flush(self, timeout: float) -> None:
        self.flushed = True


class DownInspector:
    def inspect(self, content: str) -> list[Finding]:
        raise DetectorUnavailableError


def _traced_gateway(settings: Settings, **adapters: Any) -> tuple[TestClient, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return TestClient(create_app(settings, tracer_provider=provider, **adapters)), exporter


def _named(spans: tuple[ReadableSpan, ...], name: str) -> list[ReadableSpan]:
    return [span for span in spans if span.name == name]


def test_configuring_kafka_publishes_decisions_to_the_topic(
    settings: Settings, caller_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    producers: list[RecordingProducer] = []

    def producer(**config: Any) -> RecordingProducer:
        producers.append(RecordingProducer(**config))
        return producers[-1]

    monkeypatch.setitem(sys.modules, "kafka", SimpleNamespace(KafkaProducer=producer))
    configured = settings.model_copy(
        update={"kafka_bootstrap_servers": "kafka:9092", "kafka_topic": "security.events"}
    )

    with TestClient(create_app(configured)) as client:
        response = client.post("/v1/inspect/input", headers=caller_auth, json=SENSITIVE)
        ready = client.get("/health/ready")

    assert response.status_code == 200
    assert ready.json()["audit"] == "durable"
    # Stopping the gateway flushed what the producer still held.
    assert producers[0].flushed
    [(topic, value, key)] = producers[0].messages
    assert topic == "security.events"
    assert key == b"acme"
    assert b'"evidence_categories":["pii_email"]' in value
    assert SECRET_EMAIL.encode() not in value


def test_detector_latency_is_exported_per_detector(
    client: TestClient, caller_auth: dict[str, str]
) -> None:
    client.post("/v1/inspect/input", headers=caller_auth, json=BENIGN)

    body = client.get("/metrics").text

    assert 'guardrail_detector_latency_seconds_count{detector="DeterministicInspector"} 1.0' in body
    assert "guardrail_audit_events_in_flight 0.0" in body


def test_a_failed_detector_still_reports_its_latency(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with TestClient(create_app(settings, inspectors=(DownInspector(),))) as client:
        response = client.post("/v1/inspect/input", headers=caller_auth, json=BENIGN)
        body = client.get("/metrics").text

    assert response.json()["reason_code"] == "content_inspection_unavailable"
    assert 'guardrail_detector_latency_seconds_count{detector="DownInspector"} 1.0' in body


def test_a_content_decision_is_one_span_with_a_child_span_per_detector(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    client, exporter = _traced_gateway(settings)

    with client:
        client.post("/v1/inspect/input", headers=caller_auth, json=SENSITIVE)

    spans = exporter.get_finished_spans()
    [decision] = _named(spans, "guardrail.inspect_content")
    [detector] = _named(spans, "guardrail.detector")
    assert detector.parent is not None
    assert detector.parent.span_id == decision.context.span_id
    assert detector.attributes is not None
    assert detector.attributes["guardrail.detector"] == "DeterministicInspector"
    assert dict(decision.attributes or {}) == {
        "guardrail.enforcement_point": "input",
        "guardrail.verdict": "transform",
        "guardrail.reason_code": "sensitive_content_redacted",
        "guardrail.policy_version": "test-policy",
        "guardrail.trace_id": TRACE,
        "guardrail.evidence_categories": ("pii_email",),
    }


def test_an_action_decision_is_traced(settings: Settings, caller_auth: dict[str, str]) -> None:
    client, exporter = _traced_gateway(settings)

    with client:
        client.post("/v1/inspect/action", headers=caller_auth, json=ACTION)

    [span] = _named(exporter.get_finished_spans(), "guardrail.inspect_action")
    assert span.attributes is not None
    assert span.attributes["guardrail.enforcement_point"] == "action"
    assert span.attributes["guardrail.verdict"] == "require_approval"


def test_a_context_batch_is_traced(settings: Settings, caller_auth: dict[str, str]) -> None:
    client, exporter = _traced_gateway(settings)
    batch = {
        "identity": "user-1",
        "tenant_id": "acme",
        "trace_id": TRACE,
        "documents": [
            {
                "id": "doc-1",
                "source_tenant_id": "acme",
                "content": "Refunds are issued within five days.",
            }
        ],
    }

    with client:
        response = client.post("/v1/inspect/context/batch", headers=caller_auth, json=batch)

    assert response.status_code == 200
    assert len(_named(exporter.get_finished_spans(), "guardrail.inspect_context_batch")) == 1


def test_spans_never_carry_content_tenant_or_identity(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    client, exporter = _traced_gateway(settings)

    with client:
        client.post("/v1/inspect/input", headers=caller_auth, json=SENSITIVE)
        client.post("/v1/inspect/action", headers=caller_auth, json=ACTION)

    recorded = " ".join(
        f"{span.name} {dict(span.attributes or {})}" for span in exporter.get_finished_spans()
    )
    assert SECRET_EMAIL not in recorded
    assert "acme" not in recorded
    assert "user-1" not in recorded
    assert "record_id" not in recorded


def test_no_endpoint_means_no_exporting_provider(settings: Settings) -> None:
    assert build_provider(settings) is None


def test_an_otlp_endpoint_builds_an_exporting_provider(settings: Settings) -> None:
    configured = settings.model_copy(update={"otlp_endpoint": "http://collector:4318/v1/traces"})

    provider = build_provider(configured)

    assert isinstance(provider, TracerProvider)
    assert provider.resource.attributes["service.name"] == "guardrail-gateway"
    provider.shutdown()


def test_a_missing_sdk_is_a_clear_configuration_error(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "opentelemetry.exporter.otlp.proto.http.trace_exporter", None)
    configured = settings.model_copy(update={"otlp_endpoint": "http://collector:4318/v1/traces"})

    with pytest.raises(RuntimeError, match="'otel' extra"):
        build_provider(configured)
