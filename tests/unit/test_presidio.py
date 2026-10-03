"""Unit tests for the Presidio adapter."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from guardrail_gateway.detectors import DetectorUnavailableError
from guardrail_gateway.presidio import PresidioInspector

pytestmark = pytest.mark.unit

CONTENT = "Casey Jones, SSN 078-05-1120, lives in Boston."


def _inspector(handler: Any) -> PresidioInspector:
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://presidio.test")
    return PresidioInspector("http://presidio.test", client=client)


def _results(*results: dict[str, Any]) -> Any:
    return lambda request: httpx.Response(200, json=list(results))


def test_recognized_entities_become_located_findings() -> None:
    inspector = _inspector(
        _results(
            {"entity_type": "PERSON", "start": 0, "end": 11, "score": 0.85},
            {"entity_type": "US_SSN", "start": 17, "end": 28, "score": 0.95},
        )
    )

    findings = inspector.inspect(CONTENT)

    assert [finding.evidence.category for finding in findings] == [
        "pii_person",
        "pii_government_id",
    ]
    assert CONTENT[findings[1].start : findings[1].end] == "078-05-1120"
    assert all(finding.evidence.detector == "presidio" for finding in findings)


def test_evidence_never_carries_the_recognized_value() -> None:
    inspector = _inspector(
        _results({"entity_type": "US_SSN", "start": 17, "end": 28, "score": 0.95})
    )

    evidence = inspector.inspect(CONTENT)[0].evidence

    assert "078-05-1120" not in evidence.model_dump_json()
    assert "[MATCH]" in evidence.redacted_excerpt


def test_an_unlisted_entity_type_is_still_treated_as_pii() -> None:
    inspector = _inspector(_results({"entity_type": "AU_TFN", "start": 0, "end": 5, "score": 0.7}))

    assert inspector.inspect(CONTENT)[0].evidence.category == "pii_au_tfn"


def test_the_request_carries_the_text_and_threshold() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.update(json.loads(request.content), path=request.url.path)
        return httpx.Response(200, json=[])

    assert _inspector(handler).inspect(CONTENT) == []
    assert seen == {"text": CONTENT, "language": "en", "score_threshold": 0.5, "path": "/analyze"}


def test_a_score_outside_the_unit_interval_is_clamped() -> None:
    inspector = _inspector(_results({"entity_type": "PERSON", "start": 0, "end": 5, "score": 1.7}))

    assert inspector.inspect(CONTENT)[0].evidence.score == 1.0


@pytest.mark.parametrize(
    "handler",
    [
        lambda request: httpx.Response(503),
        lambda request: httpx.Response(200, text="not json"),
        lambda request: httpx.Response(200, json={"error": "unexpected shape"}),
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused")),
        lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("slow")),
    ],
)
def test_no_usable_answer_means_the_detector_is_unavailable(handler: Any) -> None:
    with pytest.raises(DetectorUnavailableError):
        _inspector(handler).inspect(CONTENT)


@pytest.mark.parametrize(
    "result",
    [
        "PERSON",
        {"entity_type": "PERSON", "start": 0, "end": 5},
        {"entity_type": "PERSON", "start": "0", "end": 5, "score": 0.9},
        {"entity_type": 7, "start": 0, "end": 5, "score": 0.9},
        {"entity_type": "PERSON", "start": 5, "end": 5, "score": 0.9},
        {"entity_type": "PERSON", "start": 0, "end": 10_000, "score": 0.9},
        {"entity_type": "PERSON", "start": -1, "end": 5, "score": 0.9},
    ],
)
def test_a_result_that_cannot_be_read_is_not_treated_as_clean(result: Any) -> None:
    with pytest.raises(DetectorUnavailableError):
        _inspector(_results(result)).inspect(CONTENT)
