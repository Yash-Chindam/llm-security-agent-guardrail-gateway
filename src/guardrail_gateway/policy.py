"""Deterministic security policies for content and proposed tool actions."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from guardrail_gateway.detectors import DECODED_DETECTOR
from guardrail_gateway.models import (
    ActionInspectionRequest,
    DetectorEvidence,
    EnforcementPoint,
    SideEffect,
    TrustLevel,
    Verdict,
)

_ALLOWED_TOOLS: dict[str, frozenset[SideEffect]] = {
    "search_documents": frozenset({SideEffect.NONE, SideEffect.READ}),
    "execute_sql": frozenset({SideEffect.READ}),
    "send_email": frozenset({SideEffect.EXTERNAL}),
    "update_record": frozenset({SideEffect.WRITE}),
    "delete_record": frozenset({SideEffect.DESTRUCTIVE}),
}

_APPROVAL_EFFECTS = {SideEffect.WRITE, SideEffect.EXTERNAL, SideEffect.DESTRUCTIVE}
_SQL_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|grant|revoke|copy|call|execute)\b",
    re.IGNORECASE,
)


def content_verdict(
    point: EnforcementPoint,
    trust_level: TrustLevel,
    source_tenant_id: str | None,
    tenant_id: str,
    evidence: list[DetectorEvidence],
) -> tuple[Verdict, str]:
    """Evaluate detector evidence in context; detectors never authorize by themselves."""

    if source_tenant_id is not None and source_tenant_id != tenant_id:
        return Verdict.DENY, "cross_tenant_context"

    # Obfuscated matches have no position in the original text, so redaction
    # cannot make the content safe; the only sound verdict is denial.
    if any(item.detector == DECODED_DETECTOR for item in evidence):
        return Verdict.DENY, "obfuscated_content_detected"

    categories = {item.category for item in evidence}
    if categories & {"prompt_injection", "jailbreak"} and (
        point is EnforcementPoint.CONTEXT or trust_level is TrustLevel.UNTRUSTED
    ):
        return Verdict.DENY, "prompt_injection_detected"

    sensitive = bool(categories & {"secret", "pii_email", "pii_phone"})
    if sensitive and point is EnforcementPoint.OUTPUT:
        return Verdict.DENY, "sensitive_output_detected"
    if sensitive:
        return Verdict.TRANSFORM, "sensitive_content_redacted"
    return Verdict.ALLOW, "policy_allow"


def canonical_action_payload(request: ActionInspectionRequest) -> dict[str, Any]:
    """Return the security-relevant action fields in a stable representation."""

    return {
        "identity": request.identity,
        "tenant_id": request.tenant_id,
        "tool": request.tool,
        "resource": request.resource,
        "arguments": request.arguments,
        "side_effect": request.side_effect.value,
    }


def action_digest(request: ActionInspectionRequest) -> str:
    payload = json.dumps(
        canonical_action_payload(request),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def action_verdict(request: ActionInspectionRequest) -> tuple[Verdict, str]:
    allowed_effects = _ALLOWED_TOOLS.get(request.tool)
    if allowed_effects is None:
        return Verdict.DENY, "tool_not_allowlisted"
    if request.side_effect not in allowed_effects:
        return Verdict.DENY, "side_effect_mismatch"

    expected_prefix = f"tenant:{request.tenant_id}:"
    if not request.resource.startswith(expected_prefix):
        return Verdict.DENY, "resource_tenant_mismatch"

    if request.tool == "execute_sql":
        query = request.arguments.get("query")
        if not isinstance(query, str) or not query.strip():
            return Verdict.DENY, "invalid_sql_arguments"
        normalized = query.strip().rstrip(";").strip()
        if not normalized.lower().startswith("select ") or _SQL_FORBIDDEN.search(normalized):
            return Verdict.DENY, "sql_not_read_only"

    if request.tool == "send_email":
        if set(request.arguments) != {"to", "subject", "body"}:
            return Verdict.DENY, "invalid_tool_arguments"
    elif (
        request.tool in {"update_record", "delete_record"} and "record_id" not in request.arguments
    ):
        return Verdict.DENY, "invalid_tool_arguments"

    if request.side_effect in _APPROVAL_EFFECTS:
        return Verdict.REQUIRE_APPROVAL, "risky_action_requires_approval"
    return Verdict.ALLOW, "action_policy_allow"
