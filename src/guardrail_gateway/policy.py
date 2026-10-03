"""Deterministic security policies for content and proposed tool actions."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol

from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import DECODED_DETECTOR
from guardrail_gateway.identity import Role
from guardrail_gateway.models import (
    ActionInspectionRequest,
    DetectorEvidence,
    EnforcementPoint,
    SideEffect,
    TrustLevel,
    Verdict,
)
from guardrail_gateway.tools import (
    TOOLS,
    ActionPolicyConfig,
    ExecuteSqlArguments,
    FetchUrlArguments,
    ReadFileArguments,
    path_violation,
    sql_violation,
    url_violation,
    validate_arguments,
)

_APPROVAL_EFFECTS = {SideEffect.WRITE, SideEffect.EXTERNAL, SideEffect.DESTRUCTIVE}


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


def action_verdict(
    request: ActionInspectionRequest,
    roles: frozenset[Role],
    config: ActionPolicyConfig | None = None,
) -> tuple[Verdict, str]:
    """Decide a proposed tool action for a caller holding the given roles."""

    limits = config or ActionPolicyConfig()
    spec = TOOLS.get(request.tool)
    if spec is None:
        return Verdict.DENY, "tool_not_allowlisted"
    if not roles & spec.roles:
        return Verdict.DENY, "tool_not_authorized_for_role"
    if request.side_effect not in spec.effects:
        return Verdict.DENY, "side_effect_mismatch"

    expected_prefix = f"tenant:{request.tenant_id}:"
    if not request.resource.startswith(expected_prefix):
        return Verdict.DENY, "resource_tenant_mismatch"

    arguments = validate_arguments(spec, request.arguments)
    if arguments is None:
        return Verdict.DENY, "invalid_tool_arguments"

    violation: str | None = None
    if isinstance(arguments, ExecuteSqlArguments):
        violation = sql_violation(arguments.query)
    elif isinstance(arguments, ReadFileArguments):
        violation = path_violation(arguments.path, limits)
    elif isinstance(arguments, FetchUrlArguments):
        violation = url_violation(arguments.url, limits)
    if violation is not None:
        return Verdict.DENY, violation

    if request.side_effect in _APPROVAL_EFFECTS:
        return Verdict.REQUIRE_APPROVAL, "risky_action_requires_approval"
    return Verdict.ALLOW, "action_policy_allow"


class PolicyEngineUnavailableError(Exception):
    """Raised by a policy decision point that cannot evaluate right now."""


class PolicyEngine(Protocol):
    """The policy decision point; replaceable by an OPA client."""

    def content_verdict(
        self,
        point: EnforcementPoint,
        trust_level: TrustLevel,
        source_tenant_id: str | None,
        tenant_id: str,
        evidence: list[DetectorEvidence],
    ) -> tuple[Verdict, str]:
        """Return a verdict or raise PolicyEngineUnavailableError."""

    def action_verdict(
        self, request: ActionInspectionRequest, roles: frozenset[Role]
    ) -> tuple[Verdict, str]:
        """Return a verdict or raise PolicyEngineUnavailableError."""


class LocalPolicyEngine:
    """The built-in deterministic policy, evaluated in process."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._config = (
            ActionPolicyConfig(
                allowed_url_hosts=frozenset(host.lower() for host in settings.allowed_url_hosts),
                file_root=settings.file_root,
            )
            if settings is not None
            else ActionPolicyConfig()
        )

    def content_verdict(
        self,
        point: EnforcementPoint,
        trust_level: TrustLevel,
        source_tenant_id: str | None,
        tenant_id: str,
        evidence: list[DetectorEvidence],
    ) -> tuple[Verdict, str]:
        return content_verdict(point, trust_level, source_tenant_id, tenant_id, evidence)

    def action_verdict(
        self, request: ActionInspectionRequest, roles: frozenset[Role]
    ) -> tuple[Verdict, str]:
        return action_verdict(request, roles, self._config)
