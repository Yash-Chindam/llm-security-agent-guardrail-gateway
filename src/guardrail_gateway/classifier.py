"""A learned prompt-injection classifier as a source of evidence.

Section 10 of the design specification pairs deterministic detectors with a
prompt-injection classifier. Patterns catch phrasings someone thought of in
advance; a classifier catches paraphrases of them. Section 9 fixes its role:
it provides risk evidence and cannot grant authorization. A high score becomes
`prompt_injection` evidence, which policy weighs exactly as it weighs a
pattern match. A low score is not evidence of safety, and adds nothing.

The classifier is a model server inside the trusted boundary that speaks the
`/predict` protocol of Hugging Face Text Embeddings Inference: a batch of
single-text inputs, `{"inputs": [[text], [text], ...]}`, in, and for each one a
list of `{"label": ..., "score": ...}` out. Each text is wrapped in its own
list because that server reads a flat list of two strings as one sentence
pair, not as two inputs. The gateway sends the content in overlapping windows,
because these models read a few hundred tokens at a time and an injection
could otherwise hide past the first window.

Any failure to get a readable answer is an unavailable detector, which section
15 turns into a denial: content the classifier was meant to read and did not
is content that has not been inspected.
"""

from __future__ import annotations

from typing import Any

import httpx

from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import DetectorUnavailableError, Finding
from guardrail_gateway.models import DetectorEvidence

DETECTOR = "injection_classifier"
# Characters, not tokens: comfortably inside a 512-token window for ordinary
# text, with enough overlap that a sentence split by a boundary is still read
# whole by one window.
_WINDOW_CHARS = 1_200
_OVERLAP_CHARS = 200


def windows(content: str) -> list[str]:
    """Split content into overlapping windows that together cover all of it."""

    if len(content) <= _WINDOW_CHARS:
        return [content]
    step = _WINDOW_CHARS - _OVERLAP_CHARS
    return [
        content[start : start + _WINDOW_CHARS]
        for start in range(0, len(content) - _OVERLAP_CHARS, step)
    ]


class InjectionClassifierInspector:
    """Ask a model server whether content reads as a prompt injection."""

    def __init__(
        self,
        url: str,
        labels: tuple[str, ...],
        threshold: float = 0.9,
        timeout_seconds: float = 2.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = url
        self._labels = frozenset(label.upper() for label in labels)
        self._threshold = threshold
        self._client = client or httpx.Client(timeout=timeout_seconds)

    @classmethod
    def from_settings(cls, settings: Settings) -> InjectionClassifierInspector:
        if settings.injection_classifier_url is None:
            raise ValueError("injection_classifier_url is not configured")
        return cls(
            settings.injection_classifier_url,
            settings.injection_classifier_labels,
            settings.injection_classifier_threshold,
            settings.injection_classifier_timeout_seconds,
        )

    def inspect(self, content: str) -> list[Finding]:
        pieces = windows(content)
        try:
            response = self._client.post(
                self._url, json={"inputs": [[piece] for piece in pieces], "truncate": True}
            )
            response.raise_for_status()
            results = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise DetectorUnavailableError from error
        # One answer per window, or the content was not all read.
        if not isinstance(results, list) or len(results) != len(pieces):
            raise DetectorUnavailableError

        score = max(self._injection_score(result) for result in results)
        if score < self._threshold:
            return []
        return [
            Finding(
                DetectorEvidence(
                    detector=DETECTOR,
                    version="1.0.0",
                    category="prompt_injection",
                    score=score,
                    threshold=self._threshold,
                    # A classifier judges the passage as a whole; there is no
                    # matched span to excerpt, and none is invented.
                    redacted_excerpt="[CLASSIFIED]",
                    explanation="A classifier judged the content to be a prompt injection.",
                )
            )
        ]

    def _injection_score(self, result: Any) -> float:
        """The highest score any injection label was given for one window."""

        if isinstance(result, dict):
            result = [result]
        if not isinstance(result, list) or not result:
            raise DetectorUnavailableError
        best = 0.0
        for entry in result:
            if not isinstance(entry, dict):
                raise DetectorUnavailableError
            label, score = entry.get("label"), entry.get("score")
            if not isinstance(label, str) or isinstance(score, bool):
                raise DetectorUnavailableError
            if not isinstance(score, int | float) or not 0 <= score <= 1:
                raise DetectorUnavailableError
            if label.upper() in self._labels:
                best = max(best, float(score))
        return best
