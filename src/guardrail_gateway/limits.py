"""Request quotas and per-trace execution budgets.

Section 5 of the design specification names resource exhaustion as a threat
(a request that creates loops or excessive model and tool use) and answers it
with rate limits and budgets. Section 8.1 inspects quota before the model, and
section 8.4 inspects an execution budget before a tool action.

Both limiters are in-process and bounded. State is kept per key in least
recently used order, so a caller cannot grow the gateway's memory by inventing
identities or trace identifiers.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Hashable
from threading import RLock
from time import monotonic

_DEFAULT_MAX_KEYS = 50_000


class RateLimiter:
    """A fixed-window request counter per key."""

    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = monotonic,
        max_keys: int = _DEFAULT_MAX_KEYS,
    ) -> None:
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        # key -> (window start, requests counted in that window)
        self._windows: OrderedDict[Hashable, tuple[float, int]] = OrderedDict()
        self._lock = RLock()

    def allow(self, key: Hashable) -> bool:
        """Count one request and report whether it is within the limit."""

        now = self._clock()
        with self._lock:
            started, count = self._windows.get(key, (now, 0))
            if now - started >= self._window:
                started, count = now, 0
            if count >= self._limit:
                self._windows.move_to_end(key)
                return False
            self._windows[key] = (started, count + 1)
            self._windows.move_to_end(key)
            self._evict()
            return True

    def _evict(self) -> None:
        while len(self._windows) > self._max_keys:
            self._windows.popitem(last=False)


class ExecutionBudget:
    """A cap on how many actions one trace may propose.

    An agent stuck in a loop proposes action after action under the same trace.
    Counting them bounds the damage of a runaway chain whatever each individual
    action is, including ones that would otherwise be allowed.
    """

    def __init__(self, max_actions: int, max_keys: int = _DEFAULT_MAX_KEYS) -> None:
        self._max_actions = max_actions
        self._max_keys = max_keys
        self._spent: OrderedDict[Hashable, int] = OrderedDict()
        self._lock = RLock()

    def consume(self, key: Hashable) -> bool:
        """Spend one action and report whether the trace is still in budget."""

        with self._lock:
            spent = self._spent.get(key, 0)
            self._spent[key] = min(spent + 1, self._max_actions + 1)
            self._spent.move_to_end(key)
            while len(self._spent) > self._max_keys:
                self._spent.popitem(last=False)
            return spent < self._max_actions


class ViolationHistory:
    """Counts an identity's recent policy violations to lock out a repeat offender.

    Section 8.1 inspects known policy violations before the model. An identity
    that keeps sending injections is probing for a bypass, and each attempt it
    is allowed is another sample of the detector's blind spots.
    """

    def __init__(
        self,
        threshold: int,
        window_seconds: float,
        clock: Callable[[], float] = monotonic,
        max_keys: int = _DEFAULT_MAX_KEYS,
    ) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._events: OrderedDict[Hashable, tuple[float, int]] = OrderedDict()
        self._lock = RLock()

    def record(self, key: Hashable) -> None:
        if self._threshold <= 0:
            return
        now = self._clock()
        with self._lock:
            started, count = self._events.get(key, (now, 0))
            if now - started >= self._window:
                started, count = now, 0
            self._events[key] = (started, min(count + 1, self._threshold))
            self._events.move_to_end(key)
            while len(self._events) > self._max_keys:
                self._events.popitem(last=False)

    def locked(self, key: Hashable) -> bool:
        if self._threshold <= 0:
            return False
        now = self._clock()
        with self._lock:
            started, count = self._events.get(key, (now, 0))
            return now - started < self._window and count >= self._threshold
