"""OpenTelemetry traces for enforcement decisions.

Section 17 of the design specification tracks policy and detector latency, and
section 18 places Tempo in the deployment. Each enforcement call is one span,
with one child span per detector, so a slow decision can be attributed to the
dependency that caused it.

Span attributes carry the enforcement point, verdict, reason code, policy
version, and evidence categories. They never carry content, arguments, tenant,
or identity: a trace backend is read more widely than the audit log.

Only the OpenTelemetry API is a required dependency, and without an SDK it does
nothing. Setting `GUARDRAIL_OTLP_ENDPOINT` exports spans, which needs the
`otel` extra.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from opentelemetry import trace

from guardrail_gateway.config import Settings
from guardrail_gateway.models import SecurityDecision

TRACER_NAME = "guardrail_gateway"
SERVICE_NAME = "guardrail-gateway"


def tracer_for(provider: trace.TracerProvider | None) -> trace.Tracer:
    return (provider or trace.get_tracer_provider()).get_tracer(TRACER_NAME)


def record_decision(decision: SecurityDecision) -> None:
    """Describe a decision on the span of the enforcement call that made it."""

    trace.get_current_span().set_attributes(
        {
            "guardrail.enforcement_point": decision.enforcement_point.value,
            "guardrail.verdict": decision.verdict.value,
            "guardrail.reason_code": decision.reason_code,
            "guardrail.policy_version": decision.policy_version,
            "guardrail.trace_id": str(decision.trace_id),
            "guardrail.evidence_categories": sorted({item.category for item in decision.evidence}),
        }
    )


def build_provider(settings: Settings) -> trace.TracerProvider | None:
    """An exporting tracer provider when an OTLP endpoint is configured."""

    if settings.otlp_endpoint is None:
        return None
    try:
        sdk: Any = import_module("opentelemetry.sdk.trace")
        export: Any = import_module("opentelemetry.sdk.trace.export")
        resources: Any = import_module("opentelemetry.sdk.resources")
        otlp: Any = import_module("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    except ImportError as error:
        raise RuntimeError(
            "otlp_endpoint is set but the OpenTelemetry SDK is not installed; "
            "install the 'otel' extra"
        ) from error
    provider = sdk.TracerProvider(
        resource=resources.Resource.create({"service.name": SERVICE_NAME})
    )
    # Batched and off the request path: a slow collector never delays a decision.
    provider.add_span_processor(
        export.BatchSpanProcessor(otlp.OTLPSpanExporter(endpoint=settings.otlp_endpoint))
    )
    exporting: trace.TracerProvider = provider
    return exporting
