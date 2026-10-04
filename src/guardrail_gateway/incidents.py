"""The decision log an auditor reads, and the incident cases built on it.

Section 13 of the design specification defines an IncidentCase that relates
decisions and traces to a tenant, a severity, a disposition, and a remediation.
Section 3 gives an auditor the job of inspecting policy decisions and evidence,
and a reviewer the job of adjudicating false positives. Both need decisions to
be retrievable after the request that produced them has ended.

Decisions are stored exactly as they were returned: with redacted evidence and
no raw content, so the log holds nothing the caller was not already shown.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime
from threading import RLock
from typing import Protocol
from uuid import UUID

from guardrail_gateway.models import (
    Disposition,
    IncidentCase,
    IncidentStatus,
    SecurityDecision,
    Severity,
)

_OPEN = frozenset({IncidentStatus.OPEN, IncidentStatus.INVESTIGATING})


class DecisionLog:
    """A bounded record of recent decisions, retrievable by identifier or trace."""

    def __init__(self, max_decisions: int) -> None:
        self._max_decisions = max_decisions
        self._decisions: OrderedDict[UUID, SecurityDecision] = OrderedDict()
        self._lock = RLock()

    def record(self, decision: SecurityDecision) -> None:
        with self._lock:
            self._decisions[decision.decision_id] = decision
            while len(self._decisions) > self._max_decisions:
                self._decisions.popitem(last=False)

    def get(self, decision_id: UUID, tenant_id: str) -> SecurityDecision | None:
        with self._lock:
            decision = self._decisions.get(decision_id)
        if decision is None or decision.tenant_id != tenant_id:
            return None
        return decision

    def for_trace(self, trace_id: UUID, tenant_id: str) -> list[SecurityDecision]:
        with self._lock:
            return [
                decision
                for decision in self._decisions.values()
                if decision.trace_id == trace_id and decision.tenant_id == tenant_id
            ]


def _now() -> datetime:
    return datetime.now(UTC)


class IncidentRepository(Protocol):
    """Where incident cases are kept; a failing store raises StoreUnavailableError."""

    def available(self) -> bool: ...

    def open(
        self,
        tenant_id: str,
        title: str,
        severity: Severity,
        opened_by: str,
        decisions: list[SecurityDecision],
    ) -> IncidentCase: ...

    def open_for_trace(self, trace_id: UUID, tenant_id: str, title: str) -> IncidentCase | None: ...

    def attach(self, incident_id: UUID, decision: SecurityDecision) -> None: ...

    def get(self, incident_id: UUID, tenant_id: str) -> IncidentCase | None: ...

    def list(self, tenant_id: str) -> list[IncidentCase]: ...

    def update(
        self,
        incident_id: UUID,
        tenant_id: str,
        status: IncidentStatus | None,
        disposition: Disposition | None,
        remediation: str | None,
    ) -> IncidentCase | None: ...

    def open_count(self) -> int: ...


class IncidentStore:
    """In-memory adapter, for one process; SqlIncidentStore is the durable one."""

    def __init__(self, max_incidents: int, clock: Callable[[], datetime] = _now) -> None:
        self._max_incidents = max_incidents
        self._clock = clock
        self._incidents: OrderedDict[UUID, IncidentCase] = OrderedDict()
        self._lock = RLock()

    def available(self) -> bool:
        return True

    def open(
        self,
        tenant_id: str,
        title: str,
        severity: Severity,
        opened_by: str,
        decisions: list[SecurityDecision],
    ) -> IncidentCase:
        now = self._clock()
        incident = IncidentCase(
            tenant_id=tenant_id,
            title=title,
            severity=severity,
            opened_by=opened_by,
            decision_ids=[decision.decision_id for decision in decisions],
            trace_ids=list(dict.fromkeys(decision.trace_id for decision in decisions)),
            created_at=now,
            updated_at=now,
        )
        with self._lock:
            self._incidents[incident.incident_id] = incident
            while len(self._incidents) > self._max_incidents:
                self._incidents.popitem(last=False)
        return incident.model_copy(deep=True)

    def open_for_trace(self, trace_id: UUID, tenant_id: str, title: str) -> IncidentCase | None:
        """The open incident already covering a trace under this title, if any."""

        with self._lock:
            for incident in self._incidents.values():
                if (
                    incident.tenant_id == tenant_id
                    and incident.title == title
                    and incident.status in _OPEN
                    and trace_id in incident.trace_ids
                ):
                    return incident.model_copy(deep=True)
        return None

    def attach(self, incident_id: UUID, decision: SecurityDecision) -> None:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None or decision.decision_id in incident.decision_ids:
                return
            incident.decision_ids.append(decision.decision_id)
            incident.updated_at = self._clock()

    def get(self, incident_id: UUID, tenant_id: str) -> IncidentCase | None:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None or incident.tenant_id != tenant_id:
                return None
            return incident.model_copy(deep=True)

    def list(self, tenant_id: str) -> list[IncidentCase]:
        with self._lock:
            return [
                incident.model_copy(deep=True)
                for incident in reversed(self._incidents.values())
                if incident.tenant_id == tenant_id
            ]

    def update(
        self,
        incident_id: UUID,
        tenant_id: str,
        status: IncidentStatus | None,
        disposition: Disposition | None,
        remediation: str | None,
    ) -> IncidentCase | None:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None or incident.tenant_id != tenant_id:
                return None
            if status is not None:
                incident.status = status
            if disposition is not None:
                incident.disposition = disposition
            if remediation is not None:
                incident.remediation = remediation
            incident.updated_at = self._clock()
            return incident.model_copy(deep=True)

    def open_count(self) -> int:
        with self._lock:
            return sum(1 for incident in self._incidents.values() if incident.status in _OPEN)
