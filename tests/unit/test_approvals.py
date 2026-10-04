"""Unit tests for approval storage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.models import ApprovalStatus

pytestmark = pytest.mark.unit


def test_approval_is_bound_to_exact_digest_and_tenant() -> None:
    store = ApprovalStore(60)
    record = store.create("digest-a", "acme", "user-1")
    store.approve(record.approval_id, "reviewer-1", "Verified")

    assert not store.consume(record.approval_id, "digest-b", "acme")
    assert not store.consume(record.approval_id, "digest-a", "other")
    assert store.consume(record.approval_id, "digest-a", "acme")


def test_approval_is_one_time_use() -> None:
    store = ApprovalStore(60)
    record = store.create("digest-a", "acme", "user-1")
    store.approve(record.approval_id, "reviewer-1", "Verified")

    assert store.consume(record.approval_id, "digest-a", "acme")
    assert not store.consume(record.approval_id, "digest-a", "acme")


def test_a_pending_approval_cannot_be_consumed() -> None:
    store = ApprovalStore(60)
    record = store.create("digest-a", "acme", "user-1")

    assert not store.consume(record.approval_id, "digest-a", "acme")


def test_a_rejected_approval_cannot_be_consumed_or_approved() -> None:
    store = ApprovalStore(60)
    record = store.create("digest-a", "acme", "user-1")

    rejected = store.reject(record.approval_id, "reviewer-1", "Not appropriate")
    overturned = store.approve(record.approval_id, "reviewer-2", "Looks fine")

    assert rejected is not None and rejected.status is ApprovalStatus.REJECTED
    assert overturned is not None and overturned.status is ApprovalStatus.REJECTED
    assert overturned.reviewer == "reviewer-1"
    assert not store.consume(record.approval_id, "digest-a", "acme")


def test_an_unknown_approval_is_reported_as_missing() -> None:
    store = ApprovalStore(60)

    assert store.get(uuid4()) is None
    assert store.approve(uuid4(), "reviewer-1", "x") is None
    assert store.reject(uuid4(), "reviewer-1", "x") is None
    assert not store.consume(uuid4(), "digest", "acme")


def test_an_approval_expires_whether_or_not_it_was_approved() -> None:
    store = ApprovalStore(60)
    pending = store.create("digest-a", "acme", "user-1")
    approved = store.create("digest-b", "acme", "user-1")
    store.approve(approved.approval_id, "reviewer-1", "Verified")
    past = datetime.now(UTC) - timedelta(seconds=1)
    for record in store._records.values():
        record.expires_at = past

    late = store.approve(pending.approval_id, "reviewer-1", "Too late")

    assert late is not None and late.status is ApprovalStatus.EXPIRED
    assert not store.consume(approved.approval_id, "digest-b", "acme")
    stale = store.get(approved.approval_id)
    assert stale is not None and stale.status is ApprovalStatus.EXPIRED


def test_counts_report_every_status() -> None:
    store = ApprovalStore(60)
    store.create("d1", "acme", "user-1")
    approved = store.create("d2", "acme", "user-1")
    store.approve(approved.approval_id, "reviewer-1", "ok")
    rejected = store.create("d3", "acme", "user-1")
    store.reject(rejected.approval_id, "reviewer-1", "no")
    consumed = store.create("d4", "acme", "user-1")
    store.approve(consumed.approval_id, "reviewer-1", "ok")
    store.consume(consumed.approval_id, "d4", "acme")

    assert store.counts() == {
        ApprovalStatus.PENDING: 1,
        ApprovalStatus.APPROVED: 1,
        ApprovalStatus.REJECTED: 1,
        ApprovalStatus.CONSUMED: 1,
        ApprovalStatus.EXPIRED: 0,
    }


def test_the_store_is_bounded_and_its_totals_never_go_backwards() -> None:
    store = ApprovalStore(60, max_records=3)
    first = store.create("d0", "acme", "user-1")
    store.reject(first.approval_id, "reviewer-1", "no")
    for index in range(1, 6):
        store.create(f"d{index}", "acme", "user-1")

    counts = store.counts()

    assert len(store._records) == 3
    assert store.get(first.approval_id) is None
    assert counts[ApprovalStatus.REJECTED] == 1
    # Approvals evicted while still open can no longer be used, so they are
    # reported as expired rather than disappearing from the totals.
    assert counts[ApprovalStatus.EXPIRED] == 2
    assert counts[ApprovalStatus.PENDING] == 3
    assert sum(counts.values()) == 6
