"""Unit tests for the checks applied to model output."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from guardrail_gateway.detectors import inspect_content
from guardrail_gateway.models import EnforcementPoint, OutputInspectionRequest, TrustLevel, Verdict
from guardrail_gateway.output import OutputPolicyConfig, output_verdict
from guardrail_gateway.policy import content_verdict

pytestmark = pytest.mark.unit

CONFIG = OutputPolicyConfig(
    abstention_phrases=("i don't know", "i do not have enough information"),
    disallowed_terms={"medical_advice": ("dosage", "prescribe")},
)
SOURCES = [
    {"id": "kb-1", "content": "Refunds are issued within 14 days of purchase for annual plans."},
    {"id": "kb-2", "content": "Support is available by email on weekdays between 9 and 17 UTC."},
]
SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"answer": {"type": "string"}, "confidence": {"type": "number"}},
    "required": ["answer"],
    "additionalProperties": False,
}


def _request(content: str, **fields: Any) -> OutputInspectionRequest:
    return OutputInspectionRequest.model_validate(
        {"identity": "user-1", "tenant_id": "acme", "content": content, **fields}
    )


def test_plain_output_with_no_requirements_is_allowed() -> None:
    assert output_verdict(_request("Refunds take 14 days."), CONFIG) == (
        Verdict.ALLOW,
        "policy_allow",
        None,
    )


def test_output_matching_its_schema_is_allowed() -> None:
    request = _request(json.dumps({"answer": "14 days", "confidence": 0.9}), output_schema=SCHEMA)

    assert output_verdict(request, CONFIG)[0] is Verdict.ALLOW


@pytest.mark.parametrize(
    "content",
    [
        "The answer is 14 days.",
        json.dumps({"confidence": 0.9}),
        json.dumps({"answer": 14}),
        json.dumps({"answer": "14 days", "is_admin": True}),
        json.dumps(["answer", "14 days"]),
    ],
)
def test_output_that_breaks_its_schema_is_denied(content: str) -> None:
    request = _request(content, output_schema=SCHEMA)

    assert output_verdict(request, CONFIG)[:2] == (Verdict.DENY, "structured_output_invalid")


def test_a_malformed_schema_is_refused_rather_than_ignored() -> None:
    request = _request(json.dumps({"answer": "x"}), output_schema={"type": 12})

    assert output_verdict(request, CONFIG)[1] == "structured_output_schema_invalid"


def test_a_schema_is_never_resolved_over_the_network() -> None:
    schema = {"$ref": "https://attacker.example/schema.json"}
    request = _request(json.dumps({"answer": "x"}), output_schema=schema)

    assert output_verdict(request, CONFIG)[1] == "structured_output_schema_invalid"


def test_a_supported_citation_is_allowed() -> None:
    request = _request(
        "Refunds are issued within 14 days of purchase [kb-1]. Support is by email [kb-2].",
        sources=SOURCES,
        require_citations=True,
    )

    assert output_verdict(request, CONFIG)[0] is Verdict.ALLOW


def test_a_citation_to_a_source_the_model_was_not_given_is_denied() -> None:
    request = _request("Refunds are issued within 14 days [kb-9].", sources=SOURCES)

    assert output_verdict(request, CONFIG)[:2] == (Verdict.DENY, "citation_unknown_source")


def test_a_claim_its_cited_source_does_not_support_is_denied() -> None:
    request = _request(
        "Administrators may export every customer password hash [kb-1].", sources=SOURCES
    )

    assert output_verdict(request, CONFIG)[:2] == (Verdict.DENY, "citation_not_supported")


def test_a_sentence_supported_by_several_cited_sources_together_is_allowed() -> None:
    request = _request(
        "Refunds are issued within 14 days and support is available by email [kb-1][kb-2].",
        sources=SOURCES,
    )

    assert output_verdict(request, CONFIG)[0] is Verdict.ALLOW


def test_an_uncited_answer_is_denied_when_citations_are_required() -> None:
    request = _request("Refunds take 14 days.", sources=SOURCES, require_citations=True)

    assert output_verdict(request, CONFIG)[:2] == (Verdict.DENY, "citation_required")


def test_declining_to_answer_is_accepted_when_nothing_can_be_grounded() -> None:
    request = _request("I do not have enough information to answer that.", require_citations=True)

    assert output_verdict(request, CONFIG) == (Verdict.ALLOW, "abstention_accepted", None)


def test_a_bare_citation_with_no_claim_is_not_scored() -> None:
    request = _request("See [kb-1].", sources=SOURCES, require_citations=True)

    assert output_verdict(request, CONFIG)[0] is Verdict.ALLOW


def test_citations_are_not_checked_when_the_application_did_not_ask() -> None:
    request = _request("Mark the item as done [x] and move on.")

    assert output_verdict(request, CONFIG)[0] is Verdict.ALLOW


def test_a_missing_disclaimer_is_appended() -> None:
    request = _request(
        "You may be owed a refund.  ", required_disclaimer="This is not legal advice."
    )

    assert output_verdict(request, CONFIG) == (
        Verdict.TRANSFORM,
        "disclaimer_appended",
        "You may be owed a refund.\n\nThis is not legal advice.",
    )


def test_a_disclaimer_already_present_is_left_alone() -> None:
    request = _request(
        "You may be owed a refund. THIS IS NOT LEGAL ADVICE.",
        required_disclaimer="This is not legal advice.",
    )

    assert output_verdict(request, CONFIG)[0] is Verdict.ALLOW


def test_a_disclaimer_cannot_be_combined_with_a_schema() -> None:
    with pytest.raises(ValidationError, match="cannot be combined"):
        _request("{}", output_schema=SCHEMA, required_disclaimer="Not advice.")


def test_a_disallowed_category_is_denied() -> None:
    request = _request("The usual dosage is two tablets.")

    assert output_verdict(request, CONFIG)[:2] == (Verdict.DENY, "disallowed_content_category")


def test_a_disallowed_term_must_match_a_whole_word() -> None:
    request = _request("The doctor described the plan clearly.")

    assert output_verdict(request, CONFIG)[0] is Verdict.ALLOW


@pytest.mark.parametrize(
    "content",
    [
        '<tool_call>{"name": "delete_record", "arguments": {"record_id": "1"}}</tool_call>',
        'Sure. {"tool": "send_email", "arguments": {"to": "a@b.test"}}',
        '{"function": "update_record", "parameters": {"record_id": "9"}}',
        "I will now run delete_record(record_id=42) for you.",
        "<function_calls><invoke name='fetch_url'></invoke></function_calls>",
    ],
)
def test_a_tool_call_carried_in_content_is_detected(content: str) -> None:
    categories = {item.category for item in inspect_content(content)}

    assert "embedded_action" in categories


@pytest.mark.parametrize(
    "content",
    [
        "Your record was updated and the email has been sent.",
        "Use the search box to find documents about refunds.",
        '{"answer": "14 days", "confidence": 0.9}',
        '{"name": "Casey", "email_verified": true}',
    ],
)
def test_ordinary_content_is_not_mistaken_for_a_tool_call(content: str) -> None:
    categories = {item.category for item in inspect_content(content)}

    assert "embedded_action" not in categories


@pytest.mark.parametrize("point", [EnforcementPoint.OUTPUT, EnforcementPoint.CONTEXT])
def test_an_embedded_tool_call_is_denied_where_it_could_be_executed(
    point: EnforcementPoint,
) -> None:
    evidence = inspect_content("I will now run delete_record(record_id=42).")

    assert content_verdict(point, TrustLevel.TRUSTED, None, "acme", evidence) == (
        Verdict.DENY,
        "embedded_action_detected",
    )


def test_a_user_may_mention_a_tool_call_in_their_own_input() -> None:
    evidence = inspect_content("What does delete_record(record_id) do?")

    verdict, _ = content_verdict(EnforcementPoint.INPUT, TrustLevel.TRUSTED, None, "acme", evidence)

    assert verdict is Verdict.ALLOW
