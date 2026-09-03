"""Local deterministic detectors used inside the trusted boundary."""

from __future__ import annotations

import base64
import re
from binascii import Error as BinasciiError
from dataclasses import dataclass

from guardrail_gateway.models import DetectorEvidence

# Evidence recovered from decoded content has no location in the original text,
# so it can never be safely redacted in place.
DECODED_DETECTOR = "deterministic_content_decoded"


@dataclass(frozen=True, slots=True)
class MatchRule:
    category: str
    pattern: re.Pattern[str]
    score: float
    explanation: str


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

_REDACTIONS = {
    "secret": "[REDACTED_SECRET]",  # nosec B105
    "pii_email": "[REDACTED_EMAIL]",
    "pii_phone": "[REDACTED_PHONE]",
}


def _excerpt(content: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 18)
    end = min(len(content), match.end() + 18)
    prefix = "…" if start else ""
    suffix = "…" if end < len(content) else ""
    return f"{prefix}{content[start : match.start()]}[MATCH]{content[match.end() : end]}{suffix}"


_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _decoded_candidates(content: str) -> list[str]:
    """Decode base64-looking runs so obfuscated instructions are still inspected."""

    candidates: list[str] = []
    for match in _BASE64_RUN.finditer(content):
        blob = match.group().rstrip("=")
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            text = raw.decode("utf-8")
        except (BinasciiError, UnicodeDecodeError):
            continue
        if text and sum(character.isprintable() for character in text) / len(text) > 0.8:
            candidates.append(text)
    return candidates


def _scan(content: str, detector: str, suffix: str) -> list[DetectorEvidence]:
    evidence: list[DetectorEvidence] = []
    for rule in _RULES:
        for match in rule.pattern.finditer(content):
            evidence.append(
                DetectorEvidence(
                    detector=detector,
                    version="1.1.0",
                    category=rule.category,
                    score=rule.score,
                    threshold=0.8,
                    redacted_excerpt=_excerpt(content, match),
                    explanation=rule.explanation + suffix,
                )
            )
    return evidence


def inspect_content(content: str) -> list[DetectorEvidence]:
    """Return redacted evidence without retaining the matched sensitive value."""

    evidence = _scan(content, "deterministic_content", "")
    for decoded in _decoded_candidates(content):
        evidence.extend(
            _scan(decoded, DECODED_DETECTOR, " Found only after decoding embedded content.")
        )
    return evidence


def redact_sensitive_content(content: str) -> str:
    """Replace locally detected sensitive values with typed placeholders."""

    redacted = content
    for rule in _RULES:
        replacement = _REDACTIONS.get(rule.category)
        if replacement:
            redacted = rule.pattern.sub(replacement, redacted)
    return redacted
