"""Unit tests for suite scoring and the release gate."""

from __future__ import annotations

import pytest

from guardrail_gateway.redteam.models import Expectation, RedTeamRun, ScenarioResult, SuiteMetrics
from guardrail_gateway.redteam.runner import Baseline, evaluate_gate, run_suite
from guardrail_gateway.redteam.scenarios import INPUT_PATH, Probe, Scenario

pytestmark = pytest.mark.unit


class ScriptedClient:
    """Returns a queued response per call and records what it received."""

    def __init__(self, responses: list[tuple[int, dict[str, object]]]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def post(
        self, path: str, payload: dict[str, object], headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, object]]:
        self.calls.append((path, payload))
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

    run = run_suite(client, "test", "v1", (scenario,))

    assert run.results[0].observed is Expectation.BLOCKED
    assert run.results[0].passed


def test_a_transform_verdict_counts_as_allowed_to_continue() -> None:
    scenario = _scenario(Probe(INPUT_PATH, {"content": "pii"}), expectation=Expectation.ALLOWED)
    client = ScriptedClient([_decision("transform")])

    run = run_suite(client, "test", "v1", (scenario,))

    assert run.results[0].observed is Expectation.ALLOWED
    assert run.metrics.false_positive_rate == 0.0


def test_a_rejected_request_counts_as_blocked() -> None:
    scenario = _scenario(Probe(INPUT_PATH, {"content": "oversized"}))
    client = ScriptedClient([(422, {})])

    run = run_suite(client, "test", "v1", (scenario,))

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

    run_suite(client, "test", "v1", (scenario,))

    paths = [path for path, _ in client.calls]
    assert paths[1] == "/v1/approvals/abc/approve"
    assert client.calls[2][1]["approval_token"] == "abc"  # noqa: S105 -- field name, not a secret


def test_a_replay_probe_without_a_recorded_approval_sends_no_token() -> None:
    scenario = _scenario(Probe(INPUT_PATH, {"content": "x"}, approval_token_from=5))
    client = ScriptedClient([_decision("deny")])

    run_suite(client, "test", "v1", (scenario,))

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
    run = run_suite(ScriptedClient([]), "test", "v1", ())

    assert run.metrics.attack_success_rate == 0.0
    assert run.metrics.false_positive_rate == 0.0
    assert run.metrics.side_effect_prevention_rate == 1.0
    assert run.metrics.latency_p50_ms == 0.0
