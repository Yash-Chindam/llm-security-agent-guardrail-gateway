from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.models import ApprovalStatus


def test_approval_is_single_use_and_digest_bound() -> None:
    store = ApprovalStore(ttl_seconds=60)
    record = store.create("expected", "acme", "requester")
    approved = store.approve(record.approval_id, "reviewer", "Validated exact action")

    assert approved is not None
    assert approved.status is ApprovalStatus.APPROVED
    assert store.consume(record.approval_id, "tampered", "acme") is False
    assert store.consume(record.approval_id, "expected", "acme") is True
    assert store.consume(record.approval_id, "expected", "acme") is False
