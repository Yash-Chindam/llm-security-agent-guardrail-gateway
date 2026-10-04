"""Thread-safe exact-action approval storage."""

from __future__ import annotations

from collections import Counter, OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Protocol
from uuid import UUID

from guardrail_gateway.models import ApprovalRecord, ApprovalStatus

_DEFAULT_MAX_RECORDS = 50_000
_OPEN = frozenset({ApprovalStatus.PENDING, ApprovalStatus.APPROVED})


def _now() -> datetime:
    return datetime.now(UTC)


class ApprovalRepository(Protocol):
    """Where approvals are kept; a failing store raises StoreUnavailableError."""

    def available(self) -> bool: ...

    def create(self, digest: str, tenant_id: str, requested_by: str) -> ApprovalRecord: ...

    def get(self, approval_id: UUID) -> ApprovalRecord | None: ...

    def approve(
        self, approval_id: UUID, reviewer: str, rationale: str
    ) -> ApprovalRecord | None: ...

    def reject(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None: ...

    def consume(self, approval_id: UUID, digest: str, tenant_id: str) -> bool: ...

    def counts(self) -> dict[ApprovalStatus, int]: ...


class ApprovalStore:
    """In-memory adapter, for one process; SqlApprovalStore is the durable one."""

    def __init__(
        self,
        ttl_seconds: int,
        max_records: int = _DEFAULT_MAX_RECORDS,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_records = max_records
        self._clock = clock
        self._records: OrderedDict[UUID, ApprovalRecord] = OrderedDict()
        # Outcomes of records that have been evicted, so the totals reported
        # for approval and expiry rates never go backwards.
        self._evicted: Counter[ApprovalStatus] = Counter()
        self._lock = RLock()

    def available(self) -> bool:
        return True

    def create(self, digest: str, tenant_id: str, requested_by: str) -> ApprovalRecord:
        now = self._clock()
        record = ApprovalRecord(
            action_digest=digest,
            tenant_id=tenant_id,
            requested_by=requested_by,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        with self._lock:
            self._records[record.approval_id] = record
            while len(self._records) > self._max_records:
                _, oldest = self._records.popitem(last=False)
                self._expire(oldest)
                # An approval evicted while still open can no longer be
                # consumed, which is the same outcome as letting it expire.
                status = ApprovalStatus.EXPIRED if oldest.status in _OPEN else oldest.status
                self._evicted[status] += 1
        return record.model_copy(deep=True)

    def get(self, approval_id: UUID) -> ApprovalRecord | None:
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return None
            self._expire(record)
            return record.model_copy(deep=True)

    def approve(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None:
        return self._adjudicate(approval_id, reviewer, rationale, ApprovalStatus.APPROVED)

    def reject(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None:
        """Record a reviewer's refusal; a rejected approval can never be consumed."""

        return self._adjudicate(approval_id, reviewer, rationale, ApprovalStatus.REJECTED)

    def consume(self, approval_id: UUID, digest: str, tenant_id: str) -> bool:
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return False
            self._expire(record)
            if (
                record.status is not ApprovalStatus.APPROVED
                or record.action_digest != digest
                or record.tenant_id != tenant_id
            ):
                return False
            record.status = ApprovalStatus.CONSUMED
            return True

    def counts(self) -> dict[ApprovalStatus, int]:
        """How many approvals have reached each status, including evicted ones."""

        with self._lock:
            totals: Counter[ApprovalStatus] = Counter(self._evicted)
            for record in self._records.values():
                self._expire(record)
                totals[record.status] += 1
            return {status: totals[status] for status in ApprovalStatus}

    def _adjudicate(
        self, approval_id: UUID, reviewer: str, rationale: str, outcome: ApprovalStatus
    ) -> ApprovalRecord | None:
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return None
            self._expire(record)
            if record.status is ApprovalStatus.PENDING:
                record.reviewer = reviewer
                record.rationale = rationale
                record.status = outcome
            return record.model_copy(deep=True)

    def _expire(self, record: ApprovalRecord) -> None:
        if record.status in _OPEN and self._clock() >= record.expires_at:
            record.status = ApprovalStatus.EXPIRED
