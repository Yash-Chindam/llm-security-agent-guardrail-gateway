"""Runtime metrics in the Prometheus exposition format.

Section 17 of the design specification tracks block rates, unauthorized
tool-call and side-effect prevention, approval and expiry rates, P50 and P95
policy latency, and event-delivery lag and dropped events. Counters here are
labeled by enforcement point, verdict, and reason code only. Tenant and
identity are deliberately not labels: they are unbounded, and they would turn
a metrics endpoint into a list of who uses the system.
"""

from __future__ import annotations

from collections.abc import Callable

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from guardrail_gateway.models import ApprovalStatus, SecurityDecision

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# Policy decisions are sub-millisecond in process and tens of milliseconds
# behind a remote policy engine or detector, so the buckets cover both.
_LATENCY_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)


class GatewayMetrics:
    """One registry per application, so two gateways in a process do not collide."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self._decisions = Counter(
            "guardrail_decisions_total",
            "Security decisions by enforcement point, verdict, and reason.",
            ["enforcement_point", "verdict", "reason_code"],
            registry=self.registry,
        )
        self._latency = Histogram(
            "guardrail_decision_latency_seconds",
            "Time taken to reach a security decision.",
            ["enforcement_point"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self._rejections = Counter(
            "guardrail_credential_rejections_total",
            "Requests refused before reaching an enforcement point.",
            ["reason_code"],
            registry=self.registry,
        )
        self._approvals = Gauge(
            "guardrail_approvals",
            "Approvals by the status they have reached.",
            ["status"],
            registry=self.registry,
        )
        self._audit_pending = Gauge(
            "guardrail_audit_events_pending",
            "Audit events buffered because the transport refused them.",
            registry=self.registry,
        )
        self._audit_dropped = Gauge(
            "guardrail_audit_events_dropped",
            "Audit events lost because the outage buffer was full.",
            registry=self.registry,
        )
        self._audit_in_flight = Gauge(
            "guardrail_audit_events_in_flight",
            "Audit events sent to the transport and not yet acknowledged.",
            registry=self.registry,
        )
        self._detector_latency = Histogram(
            "guardrail_detector_latency_seconds",
            "Time one detector took to inspect content.",
            ["detector"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self._incidents = Gauge(
            "guardrail_incidents_open",
            "Incident cases that have not been resolved or closed.",
            registry=self.registry,
        )

    def observe(self, decision: SecurityDecision) -> None:
        point = decision.enforcement_point.value
        self._decisions.labels(point, decision.verdict.value, decision.reason_code).inc()
        self._latency.labels(point).observe(decision.latency_ms / 1_000)

    def observe_detector(self, detector: str, seconds: float) -> None:
        self._detector_latency.labels(detector).observe(seconds)

    def observe_rejection(self, reason_code: str) -> None:
        self._rejections.labels(reason_code).inc()

    def render(
        self,
        approvals: Callable[[], dict[ApprovalStatus, int]],
        audit_pending: int,
        audit_dropped: int,
        incidents_open: int,
        audit_in_flight: int = 0,
    ) -> bytes:
        """Refresh the values read from other components, then serialize."""

        for status, count in approvals().items():
            self._approvals.labels(status.value).set(count)
        self._audit_pending.set(audit_pending)
        self._audit_dropped.set(audit_dropped)
        self._audit_in_flight.set(audit_in_flight)
        self._incidents.set(incidents_open)
        return generate_latest(self.registry)
