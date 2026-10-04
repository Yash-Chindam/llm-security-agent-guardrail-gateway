"""Approvals and incidents kept in a database, through the HTTP API."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from guardrail_gateway.app import create_app
from guardrail_gateway.config import Settings
from guardrail_gateway.identity import Role, issue_token
from guardrail_gateway.models import (
    ApprovalRecord,
    ApprovalStatus,
    Disposition,
    IncidentCase,
    IncidentStatus,
    SecurityDecision,
    Severity,
)
from guardrail_gateway.stores import StoreUnavailableError

pytestmark = pytest.mark.integration

CANARY = "canary-fixture-not-a-secret"
ACTION = {
    "identity": "user-1",
    "tenant_id": "acme",
    "tool": "delete_record",
    "resource": "tenant:acme:orders",
    "arguments": {"record_id": "9"},
    "side_effect": "destructive",
}
READ = {
    "identity": "user-1",
    "tenant_id": "acme",
    "tool": "search_documents",
    "resource": "tenant:acme:kb",
    "arguments": {"q": "refund policy"},
    "side_effect": "read",
}


def _durable(settings: Settings, tmp_path: Path, **changes: Any) -> Settings:
    url = SecretStr(f"sqlite:///{tmp_path / 'gateway.db'}")
    return settings.model_copy(update={"database_url": url, **changes})


def _auditor(settings: Settings) -> dict[str, str]:
    token = issue_token(settings, "auditor-1", "acme", roles=(Role.AUDITOR,))
    return {"Authorization": f"Bearer {token}"}


class DownApprovals:
    """An approval store whose database cannot be reached."""

    def available(self) -> bool:
        return False

    def create(self, digest: str, tenant_id: str, requested_by: str) -> ApprovalRecord:
        raise StoreUnavailableError

    def get(self, approval_id: UUID) -> ApprovalRecord | None:
        raise StoreUnavailableError

    def approve(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None:
        raise StoreUnavailableError

    def reject(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None:
        raise StoreUnavailableError

    def consume(self, approval_id: UUID, digest: str, tenant_id: str) -> bool:
        raise StoreUnavailableError

    def counts(self) -> dict[ApprovalStatus, int]:
        raise StoreUnavailableError


class DownIncidents:
    def available(self) -> bool:
        return False

    def open(
        self,
        tenant_id: str,
        title: str,
        severity: Severity,
        opened_by: str,
        decisions: list[SecurityDecision],
    ) -> IncidentCase:
        raise StoreUnavailableError

    def open_for_trace(self, trace_id: UUID, tenant_id: str, title: str) -> IncidentCase | None:
        raise StoreUnavailableError

    def attach(self, incident_id: UUID, decision: SecurityDecision) -> None:
        raise StoreUnavailableError

    def get(self, incident_id: UUID, tenant_id: str) -> IncidentCase | None:
        raise StoreUnavailableError

    def list(self, tenant_id: str) -> list[IncidentCase]:
        raise StoreUnavailableError

    def update(
        self,
        incident_id: UUID,
        tenant_id: str,
        status: IncidentStatus | None,
        disposition: Disposition | None,
        remediation: str | None,
    ) -> IncidentCase | None:
        raise StoreUnavailableError

    def open_count(self) -> int:
        raise StoreUnavailableError


def test_an_approval_granted_before_a_restart_is_honoured_after_it(
    settings: Settings,
    tmp_path: Path,
    caller_auth: dict[str, str],
    reviewer_auth: dict[str, str],
) -> None:
    durable = _durable(settings, tmp_path)

    with TestClient(create_app(durable)) as before:
        held = before.post("/v1/inspect/action", headers=caller_auth, json=ACTION).json()
        approval_id = held["approval_id"]
        before.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=reviewer_auth,
            json={"rationale": "Verified with the owner"},
        )

    with TestClient(create_app(durable)) as after:
        stored = after.get(f"/v1/approvals/{approval_id}", headers=caller_auth)
        used = after.post(
            "/v1/inspect/action",
            headers=caller_auth,
            json={**ACTION, "approval_token": approval_id},
        )

    assert stored.json()["status"] == "approved"
    assert used.json()["reason_code"] == "exact_action_approval_consumed"


def test_an_approval_is_consumed_once_across_two_replicas(
    settings: Settings,
    tmp_path: Path,
    caller_auth: dict[str, str],
    reviewer_auth: dict[str, str],
) -> None:
    durable = _durable(settings, tmp_path)

    with TestClient(create_app(durable)) as one, TestClient(create_app(durable)) as two:
        approval_id = one.post("/v1/inspect/action", headers=caller_auth, json=ACTION).json()[
            "approval_id"
        ]
        # Reviewed on the replica that did not issue it.
        two.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=reviewer_auth,
            json={"rationale": "Verified with the owner"},
        )
        replay = {**ACTION, "approval_token": approval_id}
        first = one.post("/v1/inspect/action", headers=caller_auth, json=replay).json()
        second = two.post("/v1/inspect/action", headers=caller_auth, json=replay).json()

    assert first["reason_code"] == "exact_action_approval_consumed"
    assert (second["verdict"], second["reason_code"]) == ("deny", "invalid_or_expired_approval")


def test_a_canary_incident_survives_a_restart(
    settings: Settings, tmp_path: Path, caller_auth: dict[str, str]
) -> None:
    durable = _durable(settings, tmp_path, canary_secrets=(SecretStr(CANARY),))
    leak = {"identity": "user-1", "tenant_id": "acme", "content": f"marker {CANARY}"}

    with TestClient(create_app(durable)) as before:
        before.post("/v1/inspect/output", headers=caller_auth, json=leak)

    with TestClient(create_app(durable)) as after:
        cases = after.get("/v1/incidents", headers=_auditor(settings)).json()
        ready = after.get("/health/ready").json()
        metrics = after.get("/metrics").text

    assert [(case["title"], case["severity"]) for case in cases] == [
        ("Canary secret observed", "critical")
    ]
    assert ready["stores"] == "available"
    assert "guardrail_incidents_open 1.0" in metrics
    assert "guardrail_store_available 1.0" in metrics


def test_an_action_needing_approval_is_denied_while_the_store_is_down(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with TestClient(create_app(settings, approvals=DownApprovals())) as client:
        proposed = client.post("/v1/inspect/action", headers=caller_auth, json=ACTION).json()
        replayed = client.post(
            "/v1/inspect/action",
            headers=caller_auth,
            json={**ACTION, "approval_token": str(uuid4())},
        ).json()

    for decision in (proposed, replayed):
        assert decision["verdict"] == "deny"
        assert decision["reason_code"] == "approval_store_unavailable"
        assert decision["approval_id"] is None


def test_work_that_needs_no_approval_continues_while_the_store_is_down(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with TestClient(
        create_app(settings, approvals=DownApprovals(), incidents=DownIncidents())
    ) as client:
        read = client.post("/v1/inspect/action", headers=caller_auth, json=READ)
        content = client.post(
            "/v1/inspect/input",
            headers=caller_auth,
            json={"identity": "user-1", "tenant_id": "acme", "content": "Hello"},
        )
        ready = client.get("/health/ready")

    assert read.json()["verdict"] == "allow"
    assert content.json()["verdict"] == "allow"
    assert ready.status_code == 200
    assert ready.json()["stores"] == "unavailable"


def test_reading_or_adjudicating_is_refused_while_the_store_is_down(
    settings: Settings, caller_auth: dict[str, str], reviewer_auth: dict[str, str]
) -> None:
    approval_id = uuid4()

    with TestClient(
        create_app(settings, approvals=DownApprovals(), incidents=DownIncidents())
    ) as client:
        responses = [
            client.get(f"/v1/approvals/{approval_id}", headers=caller_auth),
            client.post(
                f"/v1/approvals/{approval_id}/approve",
                headers=reviewer_auth,
                json={"rationale": "Verified"},
            ),
            client.get("/v1/incidents", headers=reviewer_auth),
        ]

    for response in responses:
        assert response.status_code == 503
        assert response.json() == {"detail": "store_unavailable"}


def test_a_canary_is_still_denied_when_its_incident_cannot_be_recorded(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    configured = settings.model_copy(update={"canary_secrets": (SecretStr(CANARY),)})

    with TestClient(create_app(configured, incidents=DownIncidents())) as client:
        response = client.post(
            "/v1/inspect/output",
            headers=caller_auth,
            json={"identity": "user-1", "tenant_id": "acme", "content": f"marker {CANARY}"},
        )

    assert response.status_code == 200
    assert response.json()["reason_code"] == "canary_leak_detected"


def test_metrics_are_still_served_while_the_store_is_down(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with TestClient(
        create_app(settings, approvals=DownApprovals(), incidents=DownIncidents())
    ) as client:
        client.post("/v1/inspect/action", headers=caller_auth, json=ACTION)
        response = client.get("/metrics")

    assert response.status_code == 200
    assert "guardrail_store_available 0.0" in response.text
    assert 'reason_code="approval_store_unavailable"' in response.text


def test_the_database_url_is_never_shown() -> None:
    password = "fixture-" + "password"
    configured = Settings(database_url="postgresql://gateway:" + password + "@db/gateway")

    assert password not in repr(configured)
    assert password not in configured.model_dump_json()


def test_an_unrecognised_database_url_is_a_configuration_error() -> None:
    with pytest.raises(ValidationError, match="postgresql://"):
        Settings(database_url="mysql://db/gateway")
