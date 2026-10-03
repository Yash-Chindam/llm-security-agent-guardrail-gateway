"""Checks applied to a model's output after content inspection has passed.

Section 8.3 of the design specification inspects more than leakage after the
model: the structured-output schema, grounding and citation requirements,
disallowed content categories, and abstention or disclaimer rules. Everything
here is deterministic, so a decision can be reproduced from the request alone.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing.exceptions import Unresolvable

from guardrail_gateway.config import Settings
from guardrail_gateway.models import OutputInspectionRequest, Verdict

# A citation is a bracketed source identifier such as [1] or [kb-42].
_CITATION = re.compile(r"\[([A-Za-z0-9_.:-]{1,64})\]")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_WORD = re.compile(r"[a-z0-9]+")
# Short words carry no evidence that a sentence came from its source.
_MIN_TERM_LENGTH = 4


@dataclass(frozen=True, slots=True)
class OutputPolicyConfig:
    grounding_min_overlap: float = 0.5
    abstention_phrases: tuple[str, ...] = ()
    disallowed_terms: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @classmethod
    def from_settings(cls, settings: Settings) -> OutputPolicyConfig:
        return cls(
            grounding_min_overlap=settings.grounding_min_overlap,
            abstention_phrases=tuple(p.lower() for p in settings.abstention_phrases),
            disallowed_terms=dict(settings.disallowed_output_terms),
        )


def output_verdict(
    request: OutputInspectionRequest, config: OutputPolicyConfig
) -> tuple[Verdict, str, str | None]:
    """Return the verdict, reason code, and any transformed content."""

    content = request.content

    if _disallowed_category(content, config) is not None:
        return Verdict.DENY, "disallowed_content_category", None

    if request.output_schema is not None:
        violation = _schema_violation(content, request.output_schema)
        if violation is not None:
            return Verdict.DENY, violation, None

    if request.sources or request.require_citations:
        violation = _citation_violation(request, config)
        if violation == "abstention":
            return Verdict.ALLOW, "abstention_accepted", None
        if violation is not None:
            return Verdict.DENY, violation, None

    disclaimer = request.required_disclaimer
    if disclaimer is not None and disclaimer.lower() not in content.lower():
        return Verdict.TRANSFORM, "disclaimer_appended", f"{content.rstrip()}\n\n{disclaimer}"

    return Verdict.ALLOW, "policy_allow", None


def _disallowed_category(content: str, config: OutputPolicyConfig) -> str | None:
    lowered = content.lower()
    for category, terms in config.disallowed_terms.items():
        for term in terms:
            if re.search(rf"(?<!\w){re.escape(term.lower())}(?!\w)", lowered):
                return category
    return None


def _schema_violation(content: str, schema: dict[str, object]) -> str | None:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        return "structured_output_schema_invalid"

    try:
        document = json.loads(content)
    except ValueError:
        return "structured_output_invalid"

    try:
        valid = Draft202012Validator(schema).is_valid(document)
    except Unresolvable:
        # A reference outside the schema is never fetched; a schema that needs
        # one cannot be evaluated here and is refused rather than trusted.
        return "structured_output_schema_invalid"
    return None if valid else "structured_output_invalid"


def _citation_violation(request: OutputInspectionRequest, config: OutputPolicyConfig) -> str | None:
    sources = {source.id: _terms(source.content) for source in request.sources}
    cited_any = False

    for sentence in _SENTENCE_END.split(request.content):
        cited = _CITATION.findall(sentence)
        if not cited:
            continue
        cited_any = True
        if any(source_id not in sources for source_id in cited):
            # A citation to a source the model was never given is invented.
            return "citation_unknown_source"

        claim = _terms(_CITATION.sub(" ", sentence))
        if not claim:
            continue
        evidence: set[str] = set().union(*(sources[source_id] for source_id in cited))
        if len(claim & evidence) / len(claim) < config.grounding_min_overlap:
            return "citation_not_supported"

    if request.require_citations and not cited_any:
        lowered = request.content.lower()
        if any(phrase in lowered for phrase in config.abstention_phrases):
            # Declining to answer is the correct output when nothing can be
            # grounded, and must not be punished as an uncited claim.
            return "abstention"
        return "citation_required"
    return None


def _terms(text: str) -> set[str]:
    return {word for word in _WORD.findall(text.lower()) if len(word) >= _MIN_TERM_LENGTH}
