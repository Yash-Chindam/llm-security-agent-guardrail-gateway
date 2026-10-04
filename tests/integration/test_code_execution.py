"""Deciding and running a code action through the HTTP API."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from guardrail_gateway.app import create_app
from guardrail_gateway.audit import InMemoryTransport
from guardrail_gateway.config import Settings
from guardrail_gateway.models import SandboxResult
from guardrail_gateway.sandbox import SandboxUnavailableError

pytestmark = pytest.mark.integration

TRACE = "77777777-7777-4777-8777-777777777777"
CODE = "print(sum(range(10)))"


def _run_code(code: str = CODE, *, network: bool = False, effect: str = "none") -> dict[str, Any]:
    arguments: dict[str, Any] = {"language": "python", "code": code}
    if network:
        arguments["network"] = True
    return {
        "identity": "user-1",
        "tenant_id": "acme",
        "trace_id": TRACE,
        "tool": "run_code",
        "resource": "tenant:acme:sandbox",
        "arguments": arguments,
        "side_effect": effect,
    }


class RecordingSandbox:
    def __init__(self, result: SandboxResult | None = None) -> None:
        self.up = True
        self.fails_to_start = False
        self.runs: list[tuple[str, bool]] = []
        self.result = result or SandboxResult(
            exit_code=0, stdout="45\n", stderr="", duration_ms=12.0
        )

    def available(self) -> bool:
        return self.up

    def run(self, code: str, network: bool) -> SandboxResult:
        if self.fails_to_start:
            raise SandboxUnavailableError
        self.runs.append((code, network))
        return self.result.model_copy(update={"network": network})


def _gateway(settings: Settings, sandbox: RecordingSandbox | None, **adapters: Any) -> TestClient:
    return TestClient(create_app(settings, sandbox=sandbox, **adapters))


def test_allowed_code_runs_in_the_sandbox_without_network(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()

    with _gateway(settings, sandbox) as client:
        response = client.post("/v1/actions/execute", headers=caller_auth, json=_run_code())

    body = response.json()
    assert response.status_code == 200
    assert body["decision"]["verdict"] == "allow"
    assert body["result"] == {
        "exit_code": 0,
        "stdout": "45\n",
        "stderr": "",
        "timed_out": False,
        "output_truncated": False,
        "network": False,
        "duration_ms": 12.0,
    }
    assert sandbox.runs == [(CODE, False)]


def test_code_a_caller_may_not_propose_never_reaches_the_sandbox(
    settings: Settings, read_only_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()

    with _gateway(settings, sandbox) as client:
        body = client.post("/v1/actions/execute", headers=read_only_auth, json=_run_code()).json()

    assert body["decision"]["reason_code"] == "tool_not_authorized_for_role"
    assert body["result"] is None
    assert sandbox.runs == []


def test_network_access_declared_as_no_side_effect_is_denied(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()

    with _gateway(settings, sandbox) as client:
        body = client.post(
            "/v1/actions/execute", headers=caller_auth, json=_run_code(network=True)
        ).json()

    assert body["decision"]["reason_code"] == "network_requires_approval"
    assert body["result"] is None
    assert sandbox.runs == []


def test_code_with_network_runs_only_after_that_exact_code_is_approved(
    settings: Settings, caller_auth: dict[str, str], reviewer_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()
    proposed = _run_code("import urllib.request", network=True, effect="external")

    with _gateway(settings, sandbox) as client:
        held = client.post("/v1/actions/execute", headers=caller_auth, json=proposed).json()
        approval_id = held["decision"]["approval_id"]
        client.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=reviewer_auth,
            json={"rationale": "Fetches the public price list"},
        )
        swapped = client.post(
            "/v1/actions/execute",
            headers=caller_auth,
            json={
                **_run_code("import os; os.system('id')", network=True, effect="external"),
                "approval_token": approval_id,
            },
        ).json()
        ran = client.post(
            "/v1/actions/execute",
            headers=caller_auth,
            json={**proposed, "approval_token": approval_id},
        ).json()
        replayed = client.post(
            "/v1/actions/execute",
            headers=caller_auth,
            json={**proposed, "approval_token": approval_id},
        ).json()

    assert held["decision"]["verdict"] == "require_approval"
    assert held["result"] is None
    # The approval was for other code, so it authorizes nothing here.
    assert swapped["decision"]["reason_code"] == "invalid_or_expired_approval"
    assert swapped["result"] is None
    assert ran["decision"]["reason_code"] == "exact_action_approval_consumed"
    assert ran["result"]["network"] is True
    assert replayed["decision"]["reason_code"] == "invalid_or_expired_approval"
    assert sandbox.runs == [("import urllib.request", True)]


def test_only_code_is_executed_by_the_gateway(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()
    search = {**_run_code(), "tool": "search_documents", "arguments": {"q": "refund"}}

    with _gateway(settings, sandbox) as client:
        response = client.post("/v1/actions/execute", headers=caller_auth, json=search)

    assert response.status_code == 400
    assert response.json() == {"detail": "tool_not_executable"}
    assert sandbox.runs == []


def test_execution_needs_a_credential(settings: Settings) -> None:
    sandbox = RecordingSandbox()

    with _gateway(settings, sandbox) as client:
        response = client.post("/v1/actions/execute", json=_run_code())

    assert response.status_code == 401
    assert sandbox.runs == []


def test_without_a_sandbox_code_is_refused_and_no_approval_is_spent(
    settings: Settings, caller_auth: dict[str, str], reviewer_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()
    proposed = _run_code(network=True, effect="external")

    with _gateway(settings, sandbox) as client:
        approval_id = client.post("/v1/actions/execute", headers=caller_auth, json=proposed).json()[
            "decision"
        ]["approval_id"]
        client.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=reviewer_auth,
            json={"rationale": "Approved"},
        )
        sandbox.up = False
        refused = client.post(
            "/v1/actions/execute",
            headers=caller_auth,
            json={**proposed, "approval_token": approval_id},
        )
        sandbox.up = True
        ran = client.post(
            "/v1/actions/execute",
            headers=caller_auth,
            json={**proposed, "approval_token": approval_id},
        ).json()

    assert refused.status_code == 503
    assert refused.json() == {"detail": "sandbox_unavailable"}
    # The outage did not consume the approval, so the run succeeds afterwards.
    assert ran["decision"]["reason_code"] == "exact_action_approval_consumed"
    assert len(sandbox.runs) == 1


def test_code_execution_is_not_offered_unless_a_sandbox_is_configured(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    with _gateway(settings, None) as client:
        response = client.post("/v1/actions/execute", headers=caller_auth, json=_run_code())
        decided = client.post("/v1/inspect/action", headers=caller_auth, json=_run_code())

    assert response.status_code == 503
    # The decision endpoint still answers; it runs nothing.
    assert decided.json()["verdict"] == "allow"


def test_a_sandbox_that_fails_to_start_is_reported_as_unavailable(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()
    sandbox.fails_to_start = True

    with _gateway(settings, sandbox) as client:
        response = client.post("/v1/actions/execute", headers=caller_auth, json=_run_code())
        metrics = client.get("/metrics").text

    assert response.status_code == 503
    assert 'guardrail_sandbox_runs_total{outcome="unavailable"} 1.0' in metrics


@pytest.mark.parametrize(
    ("result", "outcome"),
    [
        (SandboxResult(exit_code=0, stdout="", stderr="", duration_ms=1), "completed"),
        (SandboxResult(exit_code=1, stdout="", stderr="boom", duration_ms=1), "failed"),
        (
            SandboxResult(exit_code=None, stdout="", stderr="", timed_out=True, duration_ms=1),
            "timed_out",
        ),
        (
            SandboxResult(
                exit_code=None, stdout="x", stderr="", output_truncated=True, duration_ms=1
            ),
            "output_limit",
        ),
    ],
)
def test_every_run_is_counted_and_audited_without_its_code_or_output(
    settings: Settings, caller_auth: dict[str, str], result: SandboxResult, outcome: str
) -> None:
    transport = InMemoryTransport(100)
    secret_code = "print('a-distinctive-marker')"
    sandbox = RecordingSandbox(result.model_copy(update={"stdout": "another-distinctive-marker"}))

    with _gateway(settings, sandbox, audit_transport=transport) as client:
        client.post("/v1/actions/execute", headers=caller_auth, json=_run_code(secret_code))
        metrics = client.get("/metrics").text

    assert f'guardrail_sandbox_runs_total{{outcome="{outcome}"}} 1.0' in metrics
    events = transport.snapshot()
    assert events[-1]["reason_code"] == f"code_execution_{outcome}"
    assert (events[-1]["tenant_id"], events[-1]["trace_id"]) == ("acme", TRACE)
    assert "distinctive-marker" not in str(events)
    assert "distinctive-marker" not in metrics


def test_shell_is_not_a_language_the_sandbox_runs(
    settings: Settings, caller_auth: dict[str, str]
) -> None:
    sandbox = RecordingSandbox()
    shell = _run_code()
    shell["arguments"] = {"language": "bash", "code": "id"}

    with _gateway(settings, sandbox) as client:
        body = client.post("/v1/actions/execute", headers=caller_auth, json=shell).json()

    assert body["decision"]["reason_code"] == "invalid_tool_arguments"
    assert sandbox.runs == []
