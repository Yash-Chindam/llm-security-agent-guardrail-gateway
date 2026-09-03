"""Execute the adversarial suite against a running gateway and score the result.

The runner speaks only HTTP against the public enforcement endpoints, so a run
exercises the same policy, evidence, and audit path as production traffic.
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from guardrail_gateway.redteam.models import (
    CategoryMetrics,
    Expectation,
    RedTeamRun,
    ScenarioResult,
    SuiteMetrics,
)
from guardrail_gateway.redteam.scenarios import ACTION_PATH, ALL_SCENARIOS, Probe, Scenario

# A request the gateway refuses to let continue unchanged.
_BLOCKING_VERDICTS = frozenset({"deny", "require_approval"})


class GatewayClient(Protocol):
    """Minimal transport contract so the suite can target any deployment."""

    def post(
        self, path: str, payload: dict[str, Any], headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, Any]]:
        """Return the status code and decoded JSON body."""


class Baseline(BaseModel):
    """Recorded outcome of a previous run, used to detect regressions.

    Attack scenarios that the gateway does not yet block are listed explicitly in
    ``known_gaps`` so that weak spots stay visible instead of being deleted from
    the dataset to flatter the metrics.
    """

    model_config = ConfigDict(extra="forbid")

    suite_version: str
    blocked_scenarios: list[str] = Field(default_factory=list)
    known_gaps: list[str] = Field(default_factory=list)
    allowed_benign: list[str] = Field(default_factory=list)
    max_false_positive_rate: float = Field(ge=0, le=1)


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    failures: list[str] = Field(default_factory=list)


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, round(fraction * (len(ordered) - 1)))
    return round(ordered[index], 3)


def _run_scenario(client: GatewayClient, scenario: Scenario) -> ScenarioResult:
    verdicts: list[str] = []
    reason_codes: list[str] = []
    approvals: dict[int, str] = {}
    latency = 0.0

    for index, probe in enumerate(scenario.probes):
        # Approve before sending, so the probe observes the reviewed state.
        if probe.approve_from is not None:
            _approve(client, approvals.get(probe.approve_from))

        payload = _payload_for(probe, approvals)
        status_code, body = client.post(probe.path, payload)

        if status_code >= 400:
            # A schema or transport rejection is a refusal to let the call continue.
            verdicts.append("deny")
            reason_codes.append(f"http_{status_code}")
            continue

        verdicts.append(str(body.get("verdict", "")))
        reason_codes.append(str(body.get("reason_code", "")))
        latency += float(body.get("latency_ms", 0.0))

        approval_id = body.get("approval_id")
        if isinstance(approval_id, str):
            approvals[index] = approval_id

    observed = (
        Expectation.BLOCKED
        if verdicts and verdicts[-1] in _BLOCKING_VERDICTS
        else Expectation.ALLOWED
    )
    return ScenarioResult(
        scenario_id=scenario.scenario_id,
        category=scenario.category,
        description=scenario.description,
        expectation=scenario.expectation,
        observed=observed,
        passed=observed is scenario.expectation,
        verdicts=verdicts,
        reason_codes=reason_codes,
        latency_ms=round(latency, 3),
    )


def _payload_for(probe: Probe, approvals: dict[int, str]) -> dict[str, Any]:
    if probe.approval_token_from is None:
        return probe.payload
    token = approvals.get(probe.approval_token_from)
    if token is None:
        return probe.payload
    return {**probe.payload, "approval_token": token}


def _approve(client: GatewayClient, approval_id: str | None) -> None:
    if approval_id is None:
        return
    client.post(
        f"/v1/approvals/{approval_id}/approve",
        {"rationale": "red-team suite reviewer approval"},
        {"X-Reviewer-Id": "reviewer@acme"},
    )


def _category_metrics(results: list[ScenarioResult]) -> list[CategoryMetrics]:
    categories: dict[str, list[ScenarioResult]] = {}
    for result in results:
        categories.setdefault(result.category, []).append(result)

    metrics: list[CategoryMetrics] = []
    for category in sorted(categories):
        items = categories[category]
        passed = sum(1 for item in items if item.passed)
        attacks = [item for item in items if item.expectation is Expectation.BLOCKED]
        succeeded = sum(1 for item in attacks if not item.passed)
        metrics.append(
            CategoryMetrics(
                category=category,
                total=len(items),
                passed=passed,
                attack_success_rate=round(succeeded / len(attacks), 4) if attacks else 0.0,
            )
        )
    return metrics


def _metrics(results: list[ScenarioResult], scenarios: tuple[Scenario, ...]) -> SuiteMetrics:
    attacks = [r for r in results if r.expectation is Expectation.BLOCKED]
    benign = [r for r in results if r.expectation is Expectation.ALLOWED]
    blocked = sum(1 for r in attacks if r.observed is Expectation.BLOCKED)
    allowed = sum(1 for r in benign if r.observed is Expectation.ALLOWED)

    action_ids = {
        scenario.scenario_id
        for scenario in scenarios
        if scenario.expectation is Expectation.BLOCKED
        and any(probe.path == ACTION_PATH for probe in scenario.probes)
    }
    action_attacks = [r for r in attacks if r.scenario_id in action_ids]
    prevented = sum(1 for r in action_attacks if r.observed is Expectation.BLOCKED)
    latencies = [r.latency_ms for r in results]

    return SuiteMetrics(
        attack_total=len(attacks),
        attack_blocked=blocked,
        attack_success_rate=round((len(attacks) - blocked) / len(attacks), 4) if attacks else 0.0,
        benign_total=len(benign),
        benign_allowed=allowed,
        false_positive_rate=round((len(benign) - allowed) / len(benign), 4) if benign else 0.0,
        side_effect_prevention_rate=(
            round(prevented / len(action_attacks), 4) if action_attacks else 1.0
        ),
        latency_p50_ms=_percentile(latencies, 0.50),
        latency_p95_ms=_percentile(latencies, 0.95),
        by_category=_category_metrics(results),
    )


def run_suite(
    client: GatewayClient,
    target: str,
    policy_version: str,
    scenarios: tuple[Scenario, ...] = ALL_SCENARIOS,
) -> RedTeamRun:
    """Run every scenario and return the scored run with section 17 metrics."""

    results = [_run_scenario(client, scenario) for scenario in scenarios]
    return RedTeamRun(
        target=target,
        policy_version=policy_version,
        results=results,
        metrics=_metrics(results, scenarios),
    )


def evaluate_gate(run: RedTeamRun, baseline: Baseline) -> GateResult:
    """Block promotion on a material regression, not on a pre-existing gap."""

    failures: list[str] = []
    recorded = (
        set(baseline.blocked_scenarios) | set(baseline.known_gaps) | set(baseline.allowed_benign)
    )
    observed = {result.scenario_id: result for result in run.results}

    for scenario_id in sorted(set(observed) - recorded):
        failures.append(f"{scenario_id}: not recorded in the baseline; refresh the baseline")

    for scenario_id in sorted(baseline.blocked_scenarios):
        result = observed.get(scenario_id)
        if result is None:
            failures.append(f"{scenario_id}: previously blocked scenario is missing from the suite")
        elif result.observed is not Expectation.BLOCKED:
            failures.append(f"{scenario_id}: regression, attack is no longer blocked")

    for scenario_id in sorted(baseline.allowed_benign):
        result = observed.get(scenario_id)
        if result is None:
            failures.append(f"{scenario_id}: benign scenario is missing from the suite")
        elif result.observed is not Expectation.ALLOWED:
            failures.append(f"{scenario_id}: regression, benign workflow is now blocked")

    if run.metrics.false_positive_rate > baseline.max_false_positive_rate:
        failures.append(
            f"false positive rate {run.metrics.false_positive_rate} exceeds the "
            f"agreed maximum {baseline.max_false_positive_rate}"
        )

    return GateResult(passed=not failures, failures=failures)
