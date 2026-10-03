"""Local deterministic detectors used inside the trusted boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from guardrail_gateway.models import DetectorEvidence
from guardrail_gateway.normalize import alternative_readings
from guardrail_gateway.tools import TOOLS

# Evidence recovered from decoded content has no location in the original text,
# so it can never be safely redacted in place.
DECODED_DETECTOR = "deterministic_content_decoded"


@dataclass(frozen=True, slots=True)
class MatchRule:
    category: str
    pattern: re.Pattern[str]
    score: float
    explanation: str


_TOOL_NAMES = "|".join(sorted(TOOLS))

_RULES: tuple[MatchRule, ...] = (
    MatchRule(
        "prompt_injection",
        re.compile(
            r"\b(ignore|disregard|override|forget)\b.{0,40}\b"
            r"(previous|prior|system|developer|security|policy|instructions?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.95,
        "Instruction attempts to override a higher-trust instruction or policy.",
    ),
    MatchRule(
        "prompt_injection",
        re.compile(
            r"\b(reveal|print|show|extract|exfiltrate)\b.{0,40}\b"
            r"(system prompt|hidden context|secret|credentials?|api keys?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.98,
        "Instruction requests protected context or credentials.",
    ),
    MatchRule(
        "prompt_injection",
        re.compile(
            r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>"
            r"|\[/?INST\]|<<\s*/?SYS\s*>>"
            r"|</?\s*untrusted_evidence\b",
            re.IGNORECASE,
        ),
        0.97,
        "Content carries chat-template control tokens that forge a message boundary.",
    ),
    MatchRule(
        "jailbreak",
        re.compile(
            r"\b(?:with|having)\s+no\s+(?:\w+\s+){0,2}"
            r"(?:restrictions?|rules?|limits?|filters?|guardrails?)\b"
            r"|\bstay in character\b"
            r"|\byou are (?:now )?(?:dan|do anything now)\b",
            re.IGNORECASE,
        ),
        0.88,
        "Content attempts to install an unrestricted persona.",
    ),
    MatchRule(
        "embedded_action",
        re.compile(
            r"<\s*/?\s*(?:tool_call|tool_use|function_call|function_calls|invoke)\b"
            r'|"(?:tool|tool_name|function|name)"\s*:\s*"[A-Za-z_][\w.-]*"[^{}]{0,200}?'
            r'"(?:arguments|parameters|args|input)"\s*:'
            rf"|\b(?:{_TOOL_NAMES})\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        0.9,
        "Content carries a tool call instead of proposing it to the action broker.",
    ),
    MatchRule(
        "secret",
        re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{16,}\b"),
        0.99,
        "A value resembles a service credential.",
    ),
    MatchRule(
        "secret",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        1.0,
        "Private key material was detected.",
    ),
    MatchRule(
        "pii_email",
        re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
        0.92,
        "An email address was detected.",
    ),
    MatchRule(
        "pii_phone",
        re.compile(r"(?<!\w)(?:\+?\d[\d .()-]{7,}\d)(?!\w)"),
        0.82,
        "A phone-number-like value was detected.",
    ),
)

_CONTEXT = 18
_DECODED_NOTE = " Found only after decoding embedded content."


@dataclass(frozen=True, slots=True)
class Finding:
    """Evidence, with where in the content it was found when that is known.

    The location never leaves the gateway: it is what lets a sensitive value
    be replaced in place, while the evidence itself carries no matched text.
    """

    evidence: DetectorEvidence
    start: int | None = None
    end: int | None = None


def _excerpt(content: str, start: int, end: int) -> str:
    left = max(0, start - _CONTEXT)
    right = min(len(content), end + _CONTEXT)
    prefix = "…" if left else ""
    suffix = "…" if right < len(content) else ""
    return f"{prefix}{content[left:start]}[MATCH]{content[end:right]}{suffix}"


def _scan(content: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in _RULES:
        for match in rule.pattern.finditer(content):
            findings.append(
                Finding(
                    DetectorEvidence(
                        detector="deterministic_content",
                        version="1.2.0",
                        category=rule.category,
                        score=rule.score,
                        threshold=0.8,
                        redacted_excerpt=_excerpt(content, match.start(), match.end()),
                        explanation=rule.explanation,
                    ),
                    match.start(),
                    match.end(),
                )
            )
    return findings


def _as_decoded(finding: Finding) -> Finding:
    """Re-label a finding from an alternative reading, which has no location."""

    evidence = finding.evidence.model_copy(
        update={
            "detector": DECODED_DETECTOR,
            "explanation": finding.evidence.explanation + _DECODED_NOTE,
        }
    )
    return Finding(evidence)


def inspect_findings(content: str) -> list[Finding]:
    """Inspect the content and every reading an encoding could be hiding."""

    findings = _scan(content)
    plain = {finding.evidence.category for finding in findings}
    hidden: set[str] = set()
    for reading in alternative_readings(content):
        for finding in _scan(reading):
            category = finding.evidence.category
            # A category already visible in the original is the same value seen
            # again through a reading, not something that was concealed.
            if category in plain or category in hidden:
                continue
            hidden.add(category)
            findings.append(_as_decoded(finding))
    return findings


def inspect_content(content: str) -> list[DetectorEvidence]:
    """Return redacted evidence without retaining the matched sensitive value."""

    return [finding.evidence for finding in inspect_findings(content)]


class DetectorUnavailableError(Exception):
    """Raised by an inspector that cannot examine content right now."""


class ContentInspector(Protocol):
    """A source of detector evidence; replaceable by Presidio or a classifier."""

    def inspect(self, content: str) -> list[Finding]:
        """Return findings or raise DetectorUnavailableError."""


class DeterministicInspector:
    """The built-in local detector, which has no external dependency to lose."""

    def inspect(self, content: str) -> list[Finding]:
        return inspect_findings(content)


class CanaryInspector:
    """Reports any sighting of a seeded canary secret.

    A canary is a value planted where only a leak could surface it, so it has
    no legitimate reason to cross any boundary. Finding one measures leakage
    directly, which section 10 asks for and no pattern can do.
    """

    def __init__(self, canaries: tuple[str, ...]) -> None:
        self._canaries = canaries

    def inspect(self, content: str) -> list[Finding]:
        findings = [
            Finding(self._evidence(_excerpt(content, at, at + len(canary))), at, at + len(canary))
            for canary in self._canaries
            for at in _occurrences(content, canary)
        ]
        if findings:
            return findings
        for reading in alternative_readings(content):
            if any(canary in reading for canary in self._canaries):
                return [Finding(self._evidence("[MATCH]", _DECODED_NOTE))]
        return []

    @staticmethod
    def _evidence(excerpt: str, note: str = "") -> DetectorEvidence:
        return DetectorEvidence(
            detector="canary",
            version="1.0.0",
            category="canary",
            score=1.0,
            threshold=1.0,
            redacted_excerpt=excerpt,
            explanation="A seeded canary secret was observed." + note,
        )


def _occurrences(content: str, value: str) -> list[int]:
    positions: list[int] = []
    at = content.find(value)
    while at != -1:
        positions.append(at)
        at = content.find(value, at + len(value))
    return positions
