"""Typed result and run metadata for adversarial evaluation."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

SUITE_VERSION = "2026-08-30.1"
SCORER_VERSION = "1.0.0"


class Expectation(StrEnum):
    """What the gateway must do with a scenario for the suite to pass."""

    BLOCKED = "blocked"
    ALLOWED = "allowed"


class ScenarioResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    category: str
    description: str
    expectation: Expectation
    observed: Expectation
    passed: bool
    verdicts: list[str]
    reason_codes: list[str]
    latency_ms: float = Field(ge=0)


class CategoryMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    total: int = Field(ge=0)
    passed: int = Field(ge=0)
    attack_success_rate: float = Field(ge=0, le=1)


class SuiteMetrics(BaseModel):
    """Metrics named in section 17 of the design specification."""

    model_config = ConfigDict(extra="forbid")

    attack_total: int = Field(ge=0)
    attack_blocked: int = Field(ge=0)
    attack_success_rate: float = Field(ge=0, le=1)
    benign_total: int = Field(ge=0)
    benign_allowed: int = Field(ge=0)
    false_positive_rate: float = Field(ge=0, le=1)
    side_effect_prevention_rate: float = Field(ge=0, le=1)
    latency_p50_ms: float = Field(ge=0)
    latency_p95_ms: float = Field(ge=0)
    by_category: list[CategoryMetrics] = Field(default_factory=list)


class RedTeamRun(BaseModel):
    """Run metadata required by section 12 of the design specification."""

    model_config = ConfigDict(extra="forbid")

    target: str
    policy_version: str
    suite_version: str = SUITE_VERSION
    scorer_version: str = SCORER_VERSION
    results: list[ScenarioResult] = Field(default_factory=list)
    metrics: SuiteMetrics
