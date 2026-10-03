"""Unit tests for suite scoring and the release gate."""

from __future__ import annotations

import pytest

from guardrail_gateway.redteam.models import Expectation, RedTeamRun, ScenarioResult, SuiteMetrics
from guardrail_gateway.redteam.runner import Baseline, CredentialSet, evaluate_gate, run_suite
from guardrail_gateway.redteam.scenarios import (
    APPROVE_PATH,
    INPUT_PATH,
    Credential,
    Probe,
    Scenario,
)

pytestmark = pytest.mark.unit

CREDENTIALS = CredentialSet(
    caller="caller-token",
    reviewer="reviewer-token",
    self_reviewer="self-reviewer-token",
    foreign_tenant="foreign-token",
    forged="forged-token",
    expired="expired-token",
)


class ScriptedClient:
    """Returns a queued response per call and records what it received."""

    def __init__(self, responses: list[tuple[int, dict[str, object]]]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.headers: list[dict[str, str]] = []

    def post(
        self, path: str, payload: dict[str, object], headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, object]]:
        self.calls.append((path, payload))
        self.headers.append(headers or {})
        if not self._responses:  # pragma: no cover - guards a mis-written test
            raise AssertionError("unexpected extra request")
        return self._responses.pop(0)


def _scenario(*probes: Probe, expectation: Expectation = Expectation.BLOCKED) -> Scenario:
    return Scenario("s1", "test_category", "description", expectation, probes)


def _decision(verdict: str, **extra: object) -> tuple[int, dict[str, object]]:
    return 200, {"verdict": verdict, "reason_code": "r", "latency_ms": 1.0, **extra}


def test_only_the_final_decision_determines_the_outcome() -> None:
    scenario = _scenario(
        Probe(INPUT_PATH, {"content": "benign"}),
        Probe(INPUT_PATH, {"content": "attack"}),
    )
    client = ScriptedClient([_decision("allow"), _decision("deny")])

    run = run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert run.results[0].observed is Expectation.BLOCKED
    assert run.results[0].passed


def test_each_probe_presents_the_credential_it_asks_for() -> None:
    scenario = _scenario(
        Probe(INPUT_PATH, {"content": "a"}),
        Probe(INPUT_PATH, {"content": "b"}, credential=Credential.FORGED),
        Probe(INPUT_PATH, {"content": "c"}, credential=Credential.ANONYMOUS),
    )
    client = ScriptedClient([_decision("allow"), (401, {}), (401, {})])

    run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert client.headers[0] == {"Authorization": "Bearer caller-token"}
    assert client.headers[1] == {"Authorization": "Bearer forged-token"}
    assert client.headers[2] == {}


def test_an_approval_probe_targets_the_approval_an_earlier_probe_created() -> None:
    scenario = _scenario(
        Probe("/v1/inspect/action", {"tool": "delete_record"}),
        Probe(
            APPROVE_PATH,
            {"rationale": "approving my own request"},
            approve_target=0,
            credential=Credential.SELF_REVIEWER,
        ),
    )
    client = ScriptedClient([_decision("require_approval", approval_id="abc"), (409, {})])

    run = run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert client.calls[1][0] == "/v1/approvals/abc/approve"
    assert client.headers[1] == {"Authorization": "Bearer self-reviewer-token"}
    assert run.results[0].reason_codes == ["r", "http_409"]
    assert run.results[0].observed is Expectation.BLOCKED


def test_an_approval_probe_without_a_target_is_not_counted_as_blocked() -> None:
    """A scenario that never produced an approval has not proven anything."""

    scenario = _scenario(
        Probe("/v1/inspect/action", {"tool": "search_documents"}),
        Probe(APPROVE_PATH, {"rationale": "nothing to approve"}, approve_target=0),
    )
    client = ScriptedClient([_decision("allow")])

    run = run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert run.results[0].reason_codes == ["r", "approval_target_missing"]
    assert run.results[0].observed is Expectation.ALLOWED
    assert not run.results[0].passed


def test_the_runner_approves_with_the_reviewer_credential() -> None:
    scenario = _scenario(
        Probe(INPUT_PATH, {"content": "first"}),
        Probe(INPUT_PATH, {"content": "second"}, approve_from=0, approval_token_from=0),
    )
    client = ScriptedClient(
        [_decision("require_approval", approval_id="abc"), (200, {}), _decision("allow")]
    )

    run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert client.calls[1][0] == "/v1/approvals/abc/approve"
    assert client.headers[1] == {"Authorization": "Bearer reviewer-token"}


def test_a_transform_verdict_counts_as_allowed_to_continue() -> None:
    scenario = _scenario(Probe(INPUT_PATH, {"content": "pii"}), expectation=Expectation.ALLOWED)
    client = ScriptedClient([_decision("transform")])

    run = run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert run.results[0].observed is Expectation.ALLOWED
    assert run.metrics.false_positive_rate == 0.0


def test_a_rejected_request_counts_as_blocked() -> None:
    scenario = _scenario(Probe(INPUT_PATH, {"content": "oversized"}))
    client = ScriptedClient([(422, {})])

    run = run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert run.results[0].observed is Expectation.BLOCKED
    assert run.results[0].reason_codes == ["http_422"]


def test_an_approval_is_granted_before_the_probe_that_replays_it() -> None:
    scenario = _scenario(
        Probe(INPUT_PATH, {"content": "first"}),
        Probe(INPUT_PATH, {"content": "second"}, approve_from=0, approval_token_from=0),
    )
    client = ScriptedClient(
        [
            _decision("require_approval", approval_id="abc"),
            (200, {}),  # the approval call
            _decision("deny"),
        ]
    )

    run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    paths = [path for path, _ in client.calls]
    assert paths[1] == "/v1/approvals/abc/approve"
    assert client.calls[2][1]["approval_token"] == "abc"


def test_a_replay_probe_without_a_recorded_approval_sends_no_token() -> None:
    scenario = _scenario(Probe(INPUT_PATH, {"content": "x"}, approval_token_from=5))
    client = ScriptedClient([_decision("deny")])

    run_suite(client, "test", "v1", CREDENTIALS, (scenario,))

    assert "approval_token" not in client.calls[0][1]


def _run(results: list[ScenarioResult], false_positive_rate: float = 0.0) -> RedTeamRun:
    return RedTeamRun(
        target="t",
        policy_version="v1",
        results=results,
        metrics=SuiteMetrics(
            attack_total=1,
            attack_blocked=1,
            attack_success_rate=0.0,
            benign_total=1,
            benign_allowed=1,
            false_positive_rate=false_positive_rate,
            side_effect_prevention_rate=1.0,
            latency_p50_ms=1.0,
            latency_p95_ms=1.0,
        ),
    )


def _result(scenario_id: str, expectation: Expectation, observed: Expectation) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=scenario_id,
        category="c",
        description="d",
        expectation=expectation,
        observed=observed,
        passed=observed is expectation,
        verdicts=["deny"],
        reason_codes=["r"],
        latency_ms=1.0,
    )


def test_the_gate_passes_when_nothing_regressed() -> None:
    run = _run([_result("a1", Expectation.BLOCKED, Expectation.BLOCKED)])
    baseline = Baseline(suite_version="v", blocked_scenarios=["a1"], max_false_positive_rate=0.0)

    assert evaluate_gate(run, baseline).passed


def test_the_gate_fails_when_a_blocked_attack_becomes_allowed() -> None:
    run = _run([_result("a1", Expectation.BLOCKED, Expectation.ALLOWED)])
    baseline = Baseline(suite_version="v", blocked_scenarios=["a1"], max_false_positive_rate=0.0)

    gate = evaluate_gate(run, baseline)

    assert not gate.passed
    assert "no longer blocked" in gate.failures[0]


def test_the_gate_tolerates_a_recorded_known_gap() -> None:
    run = _run([_result("a1", Expectation.BLOCKED, Expectation.ALLOWED)])
    baseline = Baseline(suite_version="v", known_gaps=["a1"], max_false_positive_rate=0.0)

    assert evaluate_gate(run, baseline).passed


def test_the_gate_fails_when_a_benign_workflow_becomes_blocked() -> None:
    run = _run([_result("b1", Expectation.ALLOWED, Expectation.BLOCKED)], false_positive_rate=1.0)
    baseline = Baseline(suite_version="v", allowed_benign=["b1"], max_false_positive_rate=0.0)

    gate = evaluate_gate(run, baseline)

    assert not gate.passed
    assert any("benign workflow is now blocked" in failure for failure in gate.failures)
    assert any("false positive rate" in failure for failure in gate.failures)


def test_the_gate_fails_on_an_unrecorded_scenario() -> None:
    run = _run([_result("new", Expectation.BLOCKED, Expectation.BLOCKED)])
    baseline = Baseline(suite_version="v", max_false_positive_rate=0.0)

    gate = evaluate_gate(run, baseline)

    assert not gate.passed
    assert "not recorded in the baseline" in gate.failures[0]


def test_the_gate_fails_when_a_recorded_scenario_disappears() -> None:
    run = _run([])
    baseline = Baseline(
        suite_version="v",
        blocked_scenarios=["gone"],
        allowed_benign=["also-gone"],
        max_false_positive_rate=0.0,
    )

    gate = evaluate_gate(run, baseline)

    assert not gate.passed
    assert len(gate.failures) == 2


def test_metrics_are_empty_rather_than_undefined_for_an_empty_suite() -> None:
    run = run_suite(ScriptedClient([]), "test", "v1", CREDENTIALS, ())

    assert run.metrics.attack_success_rate == 0.0
    assert run.metrics.false_positive_rate == 0.0
    assert run.metrics.side_effect_prevention_rate == 1.0
    assert run.metrics.latency_p50_ms == 0.0
