"""Microsoft Presidio as a source of PII evidence.

Section 10 of the design specification runs Presidio inside the trusted
boundary and forbids sending raw sensitive content to an external inspection
service. This adapter therefore talks only to the analyzer the deployment
points it at, and any failure to get an answer is reported as an unavailable
detector, which section 15 turns into a denial.
"""

from __future__ import annotations

from typing import Any

import httpx

from guardrail_gateway.detectors import DetectorUnavailableError, Finding
from guardrail_gateway.models import DetectorEvidence

# Presidio entity types mapped onto the gateway's categories. A type that is
# not listed is still treated as PII under its own name.
_CATEGORIES = {
    "EMAIL_ADDRESS": "pii_email",
    "PHONE_NUMBER": "pii_phone",
    "PERSON": "pii_person",
    "LOCATION": "pii_location",
    "CREDIT_CARD": "pii_financial",
    "IBAN_CODE": "pii_financial",
    "US_BANK_NUMBER": "pii_financial",
    "CRYPTO": "pii_financial",
    "US_SSN": "pii_government_id",
    "US_PASSPORT": "pii_government_id",
    "US_DRIVER_LICENSE": "pii_government_id",
    "US_ITIN": "pii_government_id",
    "UK_NHS": "pii_government_id",
    "IP_ADDRESS": "pii_network",
    "MEDICAL_LICENSE": "pii_medical",
    "DATE_TIME": "pii_date",
}
_EXCERPT_CONTEXT = 18


class PresidioInspector:
    """Calls a Presidio analyzer service and reports what it recognizes."""

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 2.0,
        score_threshold: float = 0.5,
        language: str = "en",
        client: httpx.Client | None = None,
    ) -> None:
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout_seconds)
        self._threshold = score_threshold
        self._language = language

    def inspect(self, content: str) -> list[Finding]:
        try:
            response = self._client.post(
                "/analyze",
                json={
                    "text": content,
                    "language": self._language,
                    "score_threshold": self._threshold,
                },
            )
            response.raise_for_status()
            results = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise DetectorUnavailableError from error
        if not isinstance(results, list):
            raise DetectorUnavailableError

        findings: list[Finding] = []
        for result in results:
            finding = self._finding(content, result)
            if finding is None:
                # An answer that cannot be read is no answer: the content has
                # not been inspected, so it must not pass as if it had.
                raise DetectorUnavailableError
            findings.append(finding)
        return findings

    def _finding(self, content: str, result: Any) -> Finding | None:
        if not isinstance(result, dict):
            return None
        entity, start, end, score = (
            result.get("entity_type"),
            result.get("start"),
            result.get("end"),
            result.get("score"),
        )
        if not isinstance(entity, str) or not isinstance(score, int | float):
            return None
        if not isinstance(start, int) or not isinstance(end, int):
            return None
        if not 0 <= start < end <= len(content):
            return None

        category = _CATEGORIES.get(entity, f"pii_{entity.lower()}")
        before = content[max(0, start - _EXCERPT_CONTEXT) : start]
        after = content[end : end + _EXCERPT_CONTEXT]
        return Finding(
            DetectorEvidence(
                detector="presidio",
                version="1.0.0",
                category=category,
                score=min(max(float(score), 0.0), 1.0),
                threshold=self._threshold,
                redacted_excerpt=f"{before}[MATCH]{after}",
                explanation=f"Presidio recognized {entity}.",
            ),
            start,
            end,
        )
