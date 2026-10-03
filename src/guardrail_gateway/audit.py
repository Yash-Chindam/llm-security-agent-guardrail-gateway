"""Bounded structured audit sink that excludes raw prompts and arguments."""

from __future__ import annotations

from collections import deque
from threading import RLock
from typing import Any

from guardrail_gateway.models import SecurityDecision


class AuditSink:
    def __init__(self, maxlen: int) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._lock = RLock()

    def publish(self, decision: SecurityDecision) -> None:
        event = {
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
        with self._lock:
            self._events.append(event)

    def publish_rejection(self, reason_code: str, path: str) -> None:
        """Record a credential refusal, which has no decision to attribute it to.

        Section 17 requires complete audit attribution for every action
        decision, so a request refused before it reaches an enforcement point
        still leaves a trail. Only the reason code and route are kept; the
        rejected credential is never stored.
        """

        event = {
            "enforcement_point": "credential",
            "verdict": "deny",
            "reason_code": reason_code,
            "path": path,
        }
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)
