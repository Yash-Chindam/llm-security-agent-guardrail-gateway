"""Unit tests for request quotas and execution budgets."""

from __future__ import annotations

import pytest

from guardrail_gateway.limits import ExecutionBudget, RateLimiter, ViolationHistory

pytestmark = pytest.mark.unit


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_requests_within_the_limit_are_allowed() -> None:
    limiter = RateLimiter(3, clock=Clock())

    assert [limiter.allow("a") for _ in range(3)] == [True, True, True]


def test_the_request_past_the_limit_is_refused() -> None:
    limiter = RateLimiter(3, clock=Clock())
    for _ in range(3):
        limiter.allow("a")

    assert not limiter.allow("a")
    assert not limiter.allow("a")


def test_each_key_has_its_own_limit() -> None:
    limiter = RateLimiter(1, clock=Clock())
    limiter.allow("a")

    assert not limiter.allow("a")
    assert limiter.allow("b")


def test_the_limit_resets_when_the_window_elapses() -> None:
    clock = Clock()
    limiter = RateLimiter(1, window_seconds=60, clock=clock)
    limiter.allow("a")
    clock.now = 59.9
    assert not limiter.allow("a")

    clock.now = 60.0

    assert limiter.allow("a")


def test_refused_requests_do_not_extend_the_window() -> None:
    clock = Clock()
    limiter = RateLimiter(1, window_seconds=60, clock=clock)
    limiter.allow("a")
    clock.now = 30.0
    limiter.allow("a")

    clock.now = 60.0

    assert limiter.allow("a")


def test_limiter_state_is_bounded_however_many_keys_are_invented() -> None:
    limiter = RateLimiter(1, clock=Clock(), max_keys=3)
    for key in range(100):
        limiter.allow(key)

    assert len(limiter._windows) == 3
    # The oldest keys were evicted, so they start a fresh window.
    assert limiter.allow(0)
    assert not limiter.allow(99)


def test_a_trace_may_spend_exactly_its_budget() -> None:
    budget = ExecutionBudget(3)

    assert [budget.consume("t") for _ in range(5)] == [True, True, True, False, False]


def test_each_trace_has_its_own_budget() -> None:
    budget = ExecutionBudget(1)
    budget.consume("t1")

    assert not budget.consume("t1")
    assert budget.consume("t2")


def test_budget_state_is_bounded_however_many_traces_are_invented() -> None:
    budget = ExecutionBudget(1, max_keys=3)
    for key in range(100):
        budget.consume(key)

    assert len(budget._spent) == 3


def test_an_exhausted_trace_does_not_grow_its_counter() -> None:
    budget = ExecutionBudget(2)
    for _ in range(1_000):
        budget.consume("t")

    assert budget._spent["t"] == 3


def test_an_identity_is_locked_once_it_reaches_the_threshold() -> None:
    history = ViolationHistory(3, 600, clock=Clock())
    for _ in range(2):
        history.record("a")
    assert not history.locked("a")

    history.record("a")

    assert history.locked("a")
    assert not history.locked("b")


def test_a_lockout_ends_when_the_window_elapses() -> None:
    clock = Clock()
    history = ViolationHistory(1, 600, clock=clock)
    history.record("a")
    assert history.locked("a")

    clock.now = 600.0

    assert not history.locked("a")


def test_old_violations_do_not_count_toward_a_new_window() -> None:
    clock = Clock()
    history = ViolationHistory(2, 600, clock=clock)
    history.record("a")
    clock.now = 700.0

    history.record("a")

    assert not history.locked("a")


def test_a_zero_threshold_disables_the_lockout() -> None:
    history = ViolationHistory(0, 600, clock=Clock())
    for _ in range(100):
        history.record("a")

    assert not history.locked("a")
    assert history._events == {}


def test_violation_state_is_bounded() -> None:
    history = ViolationHistory(5, 600, clock=Clock(), max_keys=3)
    for key in range(100):
        history.record(key)

    assert len(history._events) == 3
