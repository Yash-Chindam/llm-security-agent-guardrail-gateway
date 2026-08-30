"""Thread-safe exact-action approval storage for the first local milestone."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import RLock
from uuid import UUID

from guardrail_gateway.models import ApprovalRecord, ApprovalStatus


class ApprovalStore:
    """In-memory adapter; the interface is intentionally replaceable by PostgreSQL."""

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._records: dict[UUID, ApprovalRecord] = {}
        self._lock = RLock()

    def create(self, digest: str, tenant_id: str, requested_by: str) -> ApprovalRecord:
        now = datetime.now(UTC)
        record = ApprovalRecord(
            action_digest=digest,
            tenant_id=tenant_id,
            requested_by=requested_by,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        with self._lock:
            self._records[record.approval_id] = record
        return record.model_copy(deep=True)

    def get(self, approval_id: UUID) -> ApprovalRecord | None:
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return None
            self._expire(record)
            return record.model_copy(deep=True)

    def approve(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None:
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return None
            self._expire(record)
            if record.status is ApprovalStatus.PENDING:
                record.reviewer = reviewer
                record.rationale = rationale
                record.status = ApprovalStatus.APPROVED
            return record.model_copy(deep=True)

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

    @staticmethod
    def _expire(record: ApprovalRecord) -> None:
        if (
            record.status
            in {
                ApprovalStatus.PENDING,
                ApprovalStatus.APPROVED,
            }
            and datetime.now(UTC) >= record.expires_at
        ):
            record.status = ApprovalStatus.EXPIRED
