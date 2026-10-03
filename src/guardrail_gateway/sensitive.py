"""What happens to sensitive values: allow, redact, pseudonymize, or deny.

Section 10 of the design specification asks for entity categories configured
per tenant and use case, with allow, redact, pseudonymize, or deny rules, and
for reversible mappings to be kept in a separate protected store. The mapping
never appears in a decision or an audit event: only the vault can turn a
pseudonym back into the value it stands for.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from threading import RLock
from time import monotonic
from typing import Protocol

from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import Finding
from guardrail_gateway.models import EntityAction

_PSEUDONYM = re.compile(r"\[[A-Z][A-Z0-9_]{0,40}_\d{1,6}\]")
_DEFAULT_MAX_SCOPES = 10_000


def is_sensitive(category: str) -> bool:
    return category == "secret" or category.startswith("pii_")


def label(category: str) -> str:
    """The name a category is shown under in a placeholder or pseudonym."""

    return category.removeprefix("pii_").upper()


def action_resolver(settings: Settings, tenant_id: str) -> Callable[[str], EntityAction]:
    """Return the rule for each category: the tenant's, else the deployment's."""

    tenant_rules = settings.tenant_entity_actions.get(tenant_id, {})

    def resolve(category: str) -> EntityAction:
        if category in tenant_rules:
            return tenant_rules[category]
        return settings.sensitive_entity_actions.get(category, EntityAction.REDACT)

    return resolve


class PseudonymVault(Protocol):
    """The protected store of reversible mappings; replaceable by a database."""

    def tokenize(self, scope: Hashable, category: str, value: str) -> str:
        """Return the pseudonym for a value, stable within the scope."""

    def restore(self, scope: Hashable, content: str) -> tuple[str, int]:
        """Replace this scope's pseudonyms with their values; return the count."""


@dataclass(slots=True)
class _Scope:
    started: float
    by_value: dict[tuple[str, str], str] = field(default_factory=dict)
    by_token: dict[str, str] = field(default_factory=dict)


class InMemoryPseudonymVault:
    """Default adapter. Mappings expire, and the number of scopes is bounded."""

    def __init__(
        self,
        ttl_seconds: float,
        clock: Callable[[], float] = monotonic,
        max_scopes: int = _DEFAULT_MAX_SCOPES,
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._max_scopes = max_scopes
        self._scopes: OrderedDict[Hashable, _Scope] = OrderedDict()
        self._lock = RLock()

    def tokenize(self, scope: Hashable, category: str, value: str) -> str:
        with self._lock:
            entry = self._live(scope)
            if entry is None:
                entry = _Scope(started=self._clock())
                self._scopes[scope] = entry
                while len(self._scopes) > self._max_scopes:
                    self._scopes.popitem(last=False)
            self._scopes.move_to_end(scope)

            known = entry.by_value.get((category, value))
            if known is not None:
                return known
            ordinal = 1 + sum(1 for held in entry.by_value if held[0] == category)
            token = f"[{label(category)}_{ordinal}]"
            entry.by_value[(category, value)] = token
            entry.by_token[token] = value
            return token

    def restore(self, scope: Hashable, content: str) -> tuple[str, int]:
        with self._lock:
            entry = self._live(scope)
            if entry is None:
                return content, 0
            tokens = dict(entry.by_token)

        restored = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal restored
            value = tokens.get(match.group())
            if value is None:
                return match.group()
            restored += 1
            return value

        return _PSEUDONYM.sub(replace, content), restored

    def _live(self, scope: Hashable) -> _Scope | None:
        entry = self._scopes.get(scope)
        if entry is None:
            return None
        if self._clock() - entry.started >= self._ttl:
            del self._scopes[scope]
            return None
        return entry


def transform(
    content: str,
    findings: list[Finding],
    action_of: Callable[[str], EntityAction],
    tokenize: Callable[[str, str], str],
) -> str:
    """Replace each located sensitive value according to its category's rule."""

    spans: list[tuple[int, int, str, EntityAction]] = []
    for finding in findings:
        category = finding.evidence.category
        if finding.start is None or finding.end is None or not is_sensitive(category):
            continue
        action = action_of(category)
        if action in (EntityAction.REDACT, EntityAction.PSEUDONYMIZE):
            spans.append((finding.start, finding.end, category, action))

    pieces: list[str] = []
    cursor = 0
    for start, end, category, action in _merged(spans):
        pieces.append(content[cursor:start])
        if action is EntityAction.PSEUDONYMIZE:
            pieces.append(tokenize(category, content[start:end]))
        else:
            pieces.append(f"[REDACTED_{label(category)}]")
        cursor = end
    pieces.append(content[cursor:])
    return "".join(pieces)


def _merged(
    spans: list[tuple[int, int, str, EntityAction]],
) -> list[tuple[int, int, str, EntityAction]]:
    """Join overlapping spans, so two detectors finding one value replace it once."""

    merged: list[tuple[int, int, str, EntityAction]] = []
    for start, end, category, action in sorted(spans, key=lambda span: (span[0], -span[1])):
        if merged and start < merged[-1][1]:
            held_start, held_end, held_category, held_action = merged[-1]
            # Where rules disagree about one value, the irreversible one wins.
            winner = EntityAction.REDACT if EntityAction.REDACT in (action, held_action) else action
            merged[-1] = (held_start, max(end, held_end), held_category, winner)
        else:
            merged.append((start, end, category, action))
    return merged
