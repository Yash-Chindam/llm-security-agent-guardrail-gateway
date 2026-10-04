"""Deterministic security policies for content and proposed tool actions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any, Protocol

from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import DECODED_DETECTOR
from guardrail_gateway.identity import Role
from guardrail_gateway.models import (
    ActionInspectionRequest,
    DetectorEvidence,
    EnforcementPoint,
    EntityAction,
    SideEffect,
    TrustLevel,
    Verdict,
)
from guardrail_gateway.sensitive import action_resolver
from guardrail_gateway.tools import (
    TOOLS,
    ActionPolicyConfig,
    ExecuteSqlArguments,
    FetchUrlArguments,
    ReadFileArguments,
    RunCodeArguments,
    path_violation,
    sql_violation,
    url_violation,
    validate_arguments,
)

APPROVAL_EFFECTS = frozenset({SideEffect.WRITE, SideEffect.EXTERNAL, SideEffect.DESTRUCTIVE})


def content_verdict(
    point: EnforcementPoint,
    trust_level: TrustLevel,
    source_tenant_id: str | None,
    tenant_id: str,
    evidence: list[DetectorEvidence],
    action_of: Callable[[str], EntityAction] | None = None,
) -> tuple[Verdict, str]:
    """Evaluate detector evidence in context; detectors never authorize by themselves."""

    if source_tenant_id is not None and source_tenant_id != tenant_id:
        return Verdict.DENY, "cross_tenant_context"

    # A canary has no legitimate reason to be anywhere, so nothing below can
    # make its appearance acceptable.
    if any(item.category == "canary" for item in evidence):
        return Verdict.DENY, "canary_leak_detected"

    # Obfuscated matches have no position in the original text, so redaction
    # cannot make the content safe; the only sound verdict is denial.
    if any(item.detector == DECODED_DETECTOR for item in evidence):
        return Verdict.DENY, "obfuscated_content_detected"

    categories = {item.category for item in evidence}
    # A tool call belongs at the action endpoint, where it is authorized and
    # bound to an approval. One carried in model output or in a retrieved
    # document is an attempt to have it executed without either.
    if "embedded_action" in categories and point in (
        EnforcementPoint.OUTPUT,
        EnforcementPoint.CONTEXT,
    ):
        return Verdict.DENY, "embedded_action_detected"
    if categories & {"prompt_injection", "jailbreak"} and (
        point is EnforcementPoint.CONTEXT or trust_level is TrustLevel.UNTRUSTED
    ):
        return Verdict.DENY, "prompt_injection_detected"

    resolve = action_of or (lambda _category: EntityAction.REDACT)
    rules = {
        category: resolve(category)
        for category in categories
        if category == "secret" or category.startswith("pii_")
    }
    governed = {action for action in rules.values() if action is not EntityAction.ALLOW}
    if EntityAction.DENY in governed:
        return Verdict.DENY, "sensitive_content_denied"
    if governed and point is EnforcementPoint.OUTPUT:
        return Verdict.DENY, "sensitive_output_detected"
    if governed == {EntityAction.PSEUDONYMIZE}:
        return Verdict.TRANSFORM, "sensitive_content_pseudonymized"
    if governed:
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


def argument_violation(request: ActionInspectionRequest, limits: ActionPolicyConfig) -> str | None:
    """What is wrong with a registered tool's arguments, as a reason code.

    This is parsing, not policy: it reports a fact about the arguments that a
    policy decision point can act on without ever seeing them.
    """

    spec = TOOLS.get(request.tool)
    if spec is None:
        return None
    arguments = validate_arguments(spec, request.arguments)
    if arguments is None:
        return "invalid_tool_arguments"
    if isinstance(arguments, ExecuteSqlArguments):
        return sql_violation(arguments.query)
    if isinstance(arguments, ReadFileArguments):
        return path_violation(arguments.path, limits)
    if isinstance(arguments, FetchUrlArguments):
        return url_violation(arguments.url, limits)
    if (
        isinstance(arguments, RunCodeArguments)
        and arguments.network
        and request.side_effect is not SideEffect.EXTERNAL
    ):
        # Network access declared as having no side effect would skip review.
        return "network_requires_approval"
    return None


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

    violation = argument_violation(request, limits)
    if violation is not None:
        return Verdict.DENY, violation

    if request.side_effect in APPROVAL_EFFECTS:
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


def policy_available(engine: PolicyEngine) -> bool:
    """Whether the decision point can answer; an engine that cannot tell says yes."""

    probe = getattr(engine, "available", None)
    return bool(probe()) if callable(probe) else True


class LocalPolicyEngine:
    """The built-in deterministic policy, evaluated in process."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings
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
        action_of = (
            action_resolver(self._settings, tenant_id) if self._settings is not None else None
        )
        return content_verdict(point, trust_level, source_tenant_id, tenant_id, evidence, action_of)

    def action_verdict(
        self, request: ActionInspectionRequest, roles: frozenset[Role]
    ) -> tuple[Verdict, str]:
        return action_verdict(request, roles, self._config)
