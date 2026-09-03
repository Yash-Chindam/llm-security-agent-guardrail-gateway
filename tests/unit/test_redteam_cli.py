"""Unit tests for the adversarial suite command line entry point."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

import guardrail_gateway.redteam.__main__ as cli
from guardrail_gateway.redteam.models import (
    Expectation,
    RedTeamRun,
    ScenarioResult,
    SuiteMetrics,
)
from guardrail_gateway.redteam.runner import Baseline

pytestmark = pytest.mark.unit


def _result(scenario_id: str, expectation: Expectation, observed: Expectation) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=scenario_id,
        category="c",
        description="d",
        expectation=expectation,
        observed=observed,
        passed=observed is expectation,
        verdicts=["deny" if observed is Expectation.BLOCKED else "allow"],
        reason_codes=["r"],
        latency_ms=2.0,
    )


def _run(results: list[ScenarioResult]) -> RedTeamRun:
    blocked = sum(1 for r in results if r.observed is Expectation.BLOCKED)
    return RedTeamRun(
        target="http://testserver",
        policy_version="test-policy",
        results=results,
        metrics=SuiteMetrics(
            attack_total=len(results),
            attack_blocked=blocked,
            attack_success_rate=0.0,
            benign_total=0,
            benign_allowed=0,
            false_positive_rate=0.0,
            side_effect_prevention_rate=1.0,
            latency_p50_ms=2.0,
            latency_p95_ms=2.0,
        ),
    )


class FakeGatewayClient:
    """Stands in for HttpGatewayClient so CLI tests avoid real network calls."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.closed = False

    def policy_version(self) -> str:
        return "test-policy"

    def close(self) -> None:
        self.closed = True


def _write_baseline(path: Path, run: RedTeamRun, **overrides: Any) -> None:
    fields: dict[str, Any] = {
        "suite_version": run.suite_version,
        "max_false_positive_rate": 0.0,
    }
    fields.update(overrides)
    path.write_text(Baseline(**fields).model_dump_json(), encoding="utf-8")


def test_refresh_baseline_writes_blocked_gaps_and_benign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(
        [
            _result("attack-caught", Expectation.BLOCKED, Expectation.BLOCKED),
            _result("attack-missed", Expectation.BLOCKED, Expectation.ALLOWED),
            _result("benign-ok", Expectation.ALLOWED, Expectation.ALLOWED),
        ]
    )
    monkeypatch.setattr(cli, "HttpGatewayClient", FakeGatewayClient)
    monkeypatch.setattr(cli, "run_suite", lambda *a, **k: run)
    baseline_path = tmp_path / "baseline.json"

    exit_code = cli.main(
        [
            "--target",
            "http://testserver",
            "--baseline",
            str(baseline_path),
            "--refresh-baseline",
            "--max-false-positive-rate",
            "0.1",
        ]
    )

    assert exit_code == 0
    baseline = Baseline.model_validate_json(baseline_path.read_text(encoding="utf-8"))
    assert baseline.blocked_scenarios == ["attack-caught"]
    assert baseline.known_gaps == ["attack-missed"]
    assert baseline.allowed_benign == ["benign-ok"]
    assert baseline.max_false_positive_rate == 0.1


def test_gate_passes_and_prints_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _run([_result("attack-caught", Expectation.BLOCKED, Expectation.BLOCKED)])
    monkeypatch.setattr(cli, "HttpGatewayClient", FakeGatewayClient)
    monkeypatch.setattr(cli, "run_suite", lambda *a, **k: run)
    baseline_path = tmp_path / "baseline.json"
    _write_baseline(baseline_path, run, blocked_scenarios=["attack-caught"])

    exit_code = cli.main(["--target", "http://testserver", "--baseline", str(baseline_path)])

    assert exit_code == 0
    assert "release gate: pass" in capsys.readouterr().out


def test_gate_fails_and_lists_unblocked_attacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _run([_result("attack-missed", Expectation.BLOCKED, Expectation.ALLOWED)])
    monkeypatch.setattr(cli, "HttpGatewayClient", FakeGatewayClient)
    monkeypatch.setattr(cli, "run_suite", lambda *a, **k: run)
    baseline_path = tmp_path / "baseline.json"
    _write_baseline(baseline_path, run, blocked_scenarios=["attack-missed"])

    exit_code = cli.main(["--target", "http://testserver", "--baseline", str(baseline_path)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "release gate: FAIL" in output
    assert "attack-missed" in output
    assert "no longer blocked" in output


def test_report_flag_writes_run_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run([_result("attack-caught", Expectation.BLOCKED, Expectation.BLOCKED)])
    monkeypatch.setattr(cli, "HttpGatewayClient", FakeGatewayClient)
    monkeypatch.setattr(cli, "run_suite", lambda *a, **k: run)
    baseline_path = tmp_path / "baseline.json"
    _write_baseline(baseline_path, run, blocked_scenarios=["attack-caught"])
    report_path = tmp_path / "report.json"

    cli.main(
        [
            "--target",
            "http://testserver",
            "--baseline",
            str(baseline_path),
            "--report",
            str(report_path),
        ]
    )

    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["target"] == "http://testserver"


def _patch_transport(monkeypatch: pytest.MonkeyPatch, transport: httpx.BaseTransport) -> None:
    real_client_cls = httpx.Client
    monkeypatch.setattr(
        cli.httpx,
        "Client",
        lambda base_url, timeout=10.0: real_client_cls(
            transport=transport, base_url=base_url, timeout=timeout
        ),
    )


def test_http_gateway_client_posts_and_reads_policy_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ready", "policy_version": "v-http"})
        return httpx.Response(200, json={"verdict": "allow", "reason_code": "policy_allow"})

    _patch_transport(monkeypatch, httpx.MockTransport(handler))

    client = cli.HttpGatewayClient("http://testserver")
    try:
        assert client.policy_version() == "v-http"
        status_code, body = client.post(
            "/v1/inspect/input",
            {"identity": "svc.agent@acme", "tenant_id": "acme", "content": "hello there"},
        )
        assert status_code == 200
        assert body["verdict"] == "allow"
    finally:
        client.close()


def test_http_gateway_client_treats_invalid_json_as_an_empty_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_transport(
        monkeypatch, httpx.MockTransport(lambda request: httpx.Response(200, text="not-json"))
    )

    client = cli.HttpGatewayClient("http://testserver")
    status_code, body = client.post("/v1/inspect/input", {})

    assert status_code == 200
    assert body == {}


def test_http_gateway_client_treats_a_non_object_json_body_as_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_transport(
        monkeypatch,
        httpx.MockTransport(lambda request: httpx.Response(200, json=["not", "a", "dict"])),
    )

    client = cli.HttpGatewayClient("http://testserver")
    status_code, body = client.post("/v1/inspect/input", {})

    assert status_code == 200
    assert body == {}
