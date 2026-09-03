"""Command line entry point for the adversarial suite and its release gate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import httpx

from guardrail_gateway.redteam.models import Expectation, RedTeamRun
from guardrail_gateway.redteam.runner import Baseline, evaluate_gate, run_suite

DEFAULT_BASELINE = Path(__file__).with_name("baseline.json")


class HttpGatewayClient:
    """Targets the public gateway over HTTP, exactly as a real caller would."""

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def post(
        self, path: str, payload: dict[str, Any], headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, Any]]:
        response = self._client.post(path, json=payload, headers=headers)
        try:
            body = response.json()
        except ValueError:
            return response.status_code, {}
        return response.status_code, body if isinstance(body, dict) else {}

    def policy_version(self) -> str:
        response = self._client.get("/health/ready")
        body = response.json()
        return str(body.get("policy_version", "unknown"))

    def close(self) -> None:
        self._client.close()


def _refresh_baseline(run: RedTeamRun, path: Path, max_false_positive_rate: float) -> None:
    blocked = sorted(
        r.scenario_id for r in run.results if r.expectation is Expectation.BLOCKED and r.passed
    )
    gaps = sorted(
        r.scenario_id for r in run.results if r.expectation is Expectation.BLOCKED and not r.passed
    )
    benign = sorted(
        r.scenario_id for r in run.results if r.expectation is Expectation.ALLOWED and r.passed
    )
    baseline = Baseline(
        suite_version=run.suite_version,
        blocked_scenarios=blocked,
        known_gaps=gaps,
        allowed_benign=benign,
        max_false_positive_rate=max_false_positive_rate,
    )
    path.write_text(baseline.model_dump_json(indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail-redteam")
    parser.add_argument("--target", default="http://127.0.0.1:8000")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument(
        "--refresh-baseline",
        action="store_true",
        help="Record the current outcome as the new baseline instead of gating on it.",
    )
    parser.add_argument("--max-false-positive-rate", type=float, default=0.0)
    args = parser.parse_args(argv)

    client = HttpGatewayClient(args.target)
    try:
        run = run_suite(client, args.target, client.policy_version())
    finally:
        client.close()

    if args.report is not None:
        args.report.write_text(run.model_dump_json(indent=2) + "\n", encoding="utf-8")

    metrics = run.metrics
    print(f"target                      {run.target}")
    print(f"suite/scorer                {run.suite_version} / {run.scorer_version}")
    print(f"policy version              {run.policy_version}")
    print(f"attacks blocked             {metrics.attack_blocked}/{metrics.attack_total}")
    print(f"attack success rate         {metrics.attack_success_rate}")
    print(f"benign allowed              {metrics.benign_allowed}/{metrics.benign_total}")
    print(f"false positive rate         {metrics.false_positive_rate}")
    print(f"side effect prevention rate {metrics.side_effect_prevention_rate}")
    print(f"policy latency p50/p95 ms   {metrics.latency_p50_ms} / {metrics.latency_p95_ms}")

    unblocked = [r for r in run.results if r.expectation is Expectation.BLOCKED and not r.passed]
    if unblocked:
        print("\nattacks not blocked by the current policy:")
        for result in unblocked:
            print(f"  - {result.scenario_id} ({result.category})")

    if args.refresh_baseline:
        _refresh_baseline(run, args.baseline, args.max_false_positive_rate)
        print(f"\nbaseline written to {args.baseline}")
        return 0

    baseline = Baseline.model_validate_json(args.baseline.read_text(encoding="utf-8"))
    gate = evaluate_gate(run, baseline)
    if gate.passed:
        print("\nrelease gate: pass (no regression against the recorded baseline)")
        return 0

    print("\nrelease gate: FAIL")
    for failure in gate.failures:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":  # pragma: no cover - exercised through the CLI
    sys.exit(main())
