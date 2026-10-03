"""Bounded structured audit sink that excludes raw prompts and arguments.

Section 14 of the design specification publishes security events to a
transport outside the request path, and section 15 fixes what happens when that
transport is down: events are buffered within a bound, and enforcement blocks
once mandatory audit durability can no longer be met.
"""

from __future__ import annotations

from collections import deque
from threading import RLock
from typing import Any, Protocol

from guardrail_gateway.models import SecurityDecision


class TransportUnavailableError(Exception):
    """Raised by a transport that cannot accept an event right now."""


class AuditTransport(Protocol):
    """Where audit events are delivered; replaceable by a Kafka producer."""

    def send(self, event: dict[str, Any]) -> None:
        """Deliver one event or raise TransportUnavailableError."""


class InMemoryTransport:
    """Default adapter that retains the most recent events in the process."""

    def __init__(self, maxlen: int) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._lock = RLock()

    def send(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)


class AuditSink:
    def __init__(
        self,
        maxlen: int,
        transport: AuditTransport | None = None,
        mandatory: bool = True,
    ) -> None:
        self._maxlen = maxlen
        self._transport: AuditTransport = transport or InMemoryTransport(maxlen)
        self._mandatory = mandatory
        # Events the transport refused, kept in order until it recovers.
        self._pending: deque[dict[str, Any]] = deque()
        self._dropped = 0
        self._lock = RLock()

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._pending)

    @property
    def dropped(self) -> int:
        """Events lost because the buffer was full; section 17 tracks this."""

        with self._lock:
            return self._dropped

    def accepting(self) -> bool:
        """Whether another decision can still be recorded durably.

        When audit is mandatory and the outage buffer is full, the next
        decision would be unattributable, so the caller must refuse the request
        instead of enforcing without a trail.
        """

        with self._lock:
            self._flush()
            return not self._mandatory or len(self._pending) < self._maxlen

    def state(self) -> str:
        with self._lock:
            self._flush()
            if not self._pending:
                return "durable"
            if len(self._pending) < self._maxlen or not self._mandatory:
                return "buffering"
            return "blocked"

    def publish(self, decision: SecurityDecision) -> None:
        self._deliver(
            {
                "decision_id": str(decision.decision_id),
                "request_id": str(decision.request_id),
                "trace_id": str(decision.trace_id),
                "enforcement_point": decision.enforcement_point.value,
                "tenant_id": decision.tenant_id,
                "policy_version": decision.policy_version,
                "verdict": decision.verdict.value,
                "reason_code": decision.reason_code,
                "evidence_categories": [item.category for item in decision.evidence],
                "latency_ms": decision.latency_ms,
            }
        )

    def publish_rejection(self, reason_code: str, path: str) -> None:
        """Record a credential refusal, which has no decision to attribute it to.

        Section 17 requires complete audit attribution for every action
        decision, so a request refused before it reaches an enforcement point
        still leaves a trail. Only the reason code and route are kept; the
        rejected credential is never stored.
        """

        self._deliver(
            {
                "enforcement_point": "credential",
                "verdict": "deny",
                "reason_code": reason_code,
                "path": path,
            }
        )

    def publish_operation(
        self, reason_code: str, tenant_id: str, trace_id: str, count: int
    ) -> None:
        """Record an operation that is not an enforcement decision.

        Re-identifying pseudonymized data is exactly the kind of access an
        auditor needs to see, so it is recorded with who and how much, and
        never with the values themselves.
        """

        self._deliver(
            {
                "enforcement_point": "operation",
                "verdict": "allow",
                "reason_code": reason_code,
                "tenant_id": tenant_id,
                "trace_id": trace_id,
                "count": count,
            }
        )

    def _deliver(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._flush()
            # Never overtake buffered events: delivery order is audit order.
            if not self._pending:
                try:
                    self._transport.send(event)
                except TransportUnavailableError:
                    pass
                else:
                    return
            if len(self._pending) < self._maxlen:
                self._pending.append(event)
            else:
                self._dropped += 1

    def _flush(self) -> None:
        while self._pending:
            try:
                self._transport.send(self._pending[0])
            except TransportUnavailableError:
                return
            self._pending.popleft()
