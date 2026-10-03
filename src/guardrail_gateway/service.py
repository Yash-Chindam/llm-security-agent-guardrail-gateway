"""Application service that composes detectors, policy, approvals, and audit.

Section 15 of the design specification fixes the behaviour when a security
dependency fails. Each dependency is reached through a port so its failure is
an explicit condition handled here, never an unhandled error that could leave
a request half-enforced.
"""

from __future__ import annotations

from time import perf_counter
from uuid import UUID

from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.audit import AuditSink
from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import (
    ContentInspector,
    DetectorUnavailableError,
    DeterministicInspector,
    redact_sensitive_content,
)
from guardrail_gateway.identity import Principal
from guardrail_gateway.models import (
    ActionInspectionRequest,
    ContentInspectionRequest,
    DetectorEvidence,
    EnforcementPoint,
    SecurityDecision,
    SideEffect,
    Verdict,
)
from guardrail_gateway.policy import (
    LocalPolicyEngine,
    PolicyEngine,
    PolicyEngineUnavailableError,
    action_digest,
)

# Effects that change nothing outside the gateway, and so may continue under
# the built-in policy while the policy decision point is unreachable.
_READ_ONLY_EFFECTS = frozenset({SideEffect.NONE, SideEffect.READ})


class GatewayService:
    def __init__(
        self,
        settings: Settings,
        approvals: ApprovalStore,
        audit: AuditSink,
        policy: PolicyEngine | None = None,
        inspectors: tuple[ContentInspector, ...] | None = None,
    ) -> None:
        self.settings = settings
        self.approvals = approvals
        self.audit = audit
        self.policy: PolicyEngine = policy or LocalPolicyEngine()
        self.inspectors: tuple[ContentInspector, ...] = inspectors or (DeterministicInspector(),)
        self._restricted_policy = LocalPolicyEngine()

    def inspect_content(
        self,
        request: ContentInspectionRequest,
        point: EnforcementPoint,
        principal: Principal,
    ) -> SecurityDecision:
        started = perf_counter()

        def decide(
            verdict: Verdict,
            reason: str,
            evidence: list[DetectorEvidence] | None = None,
            transformed: str | None = None,
        ) -> SecurityDecision:
            return self._publish(
                SecurityDecision(
                    request_id=request.request_id,
                    trace_id=request.trace_id,
                    enforcement_point=point,
                    tenant_id=principal.tenant_id,
                    policy_version=self.settings.policy_version,
                    verdict=verdict,
                    reason_code=reason,
                    evidence=evidence or [],
                    transformed_content=transformed,
                    latency_ms=self._latency(started),
                )
            )

        if _asserts_another_identity(request.identity, request.tenant_id, principal):
            return decide(Verdict.DENY, "identity_assertion_mismatch")
        if not self.audit.accepting():
            return decide(Verdict.DENY, "audit_durability_unavailable")
        if len(request.content) > self.settings.max_content_chars:
            return decide(Verdict.DENY, "content_size_exceeded")

        try:
            evidence = self._evidence(request.content)
        except DetectorUnavailableError:
            # Uninspected content may carry anything, so it does not continue.
            return decide(Verdict.DENY, "content_inspection_unavailable")

        try:
            verdict, reason = self.policy.content_verdict(
                point, request.trust_level, request.source_tenant_id, request.tenant_id, evidence
            )
        except PolicyEngineUnavailableError:
            if not self.settings.restricted_read_only_mode:
                return decide(Verdict.DENY, "policy_engine_unavailable", evidence)
            verdict, reason = self._restricted_policy.content_verdict(
                point, request.trust_level, request.source_tenant_id, request.tenant_id, evidence
            )
            if verdict is Verdict.ALLOW:
                reason = "restricted_read_only_mode"

        transformed = (
            redact_sensitive_content(request.content) if verdict is Verdict.TRANSFORM else None
        )
        return decide(verdict, reason, evidence, transformed)

    def inspect_action(
        self, request: ActionInspectionRequest, principal: Principal
    ) -> SecurityDecision:
        started = perf_counter()

        def decide(
            verdict: Verdict,
            reason: str,
            digest: str | None = None,
            approval_id: UUID | None = None,
        ) -> SecurityDecision:
            return self._publish(
                SecurityDecision(
                    request_id=request.request_id,
                    trace_id=request.trace_id,
                    enforcement_point=EnforcementPoint.ACTION,
                    tenant_id=principal.tenant_id,
                    policy_version=self.settings.policy_version,
                    verdict=verdict,
                    reason_code=reason,
                    action_digest=digest,
                    approval_id=approval_id,
                    latency_ms=self._latency(started),
                )
            )

        if _asserts_another_identity(request.identity, request.tenant_id, principal):
            return decide(Verdict.DENY, "identity_assertion_mismatch")
        if not self.audit.accepting():
            return decide(Verdict.DENY, "audit_durability_unavailable")

        digest = action_digest(request)
        try:
            verdict, reason = self.policy.action_verdict(request)
        except PolicyEngineUnavailableError:
            # A side effect is never authorized by a fallback: without the
            # policy decision point it fails closed, whatever mode is enabled.
            restricted = (
                self.settings.restricted_read_only_mode
                and request.side_effect in _READ_ONLY_EFFECTS
            )
            if not restricted:
                return decide(Verdict.DENY, "policy_engine_unavailable", digest)
            verdict, reason = self._restricted_policy.action_verdict(request)
            if verdict is not Verdict.ALLOW:
                return decide(Verdict.DENY, reason, digest)
            reason = "restricted_read_only_mode"

        approval_id = None
        if verdict is Verdict.REQUIRE_APPROVAL:
            if request.approval_token is not None and self.approvals.consume(
                request.approval_token, digest, request.tenant_id
            ):
                verdict, reason = Verdict.ALLOW, "exact_action_approval_consumed"
                approval_id = request.approval_token
            elif request.approval_token is not None:
                verdict, reason = Verdict.DENY, "invalid_or_expired_approval"
            else:
                approval = self.approvals.create(digest, request.tenant_id, request.identity)
                approval_id = approval.approval_id

        return decide(verdict, reason, digest, approval_id)

    def _evidence(self, content: str) -> list[DetectorEvidence]:
        """Union every inspector's evidence.

        When detectors disagree, the union is the conservative reading section
        15 asks for: one detector's finding is never outvoted by another's
        silence, and policy then weighs it against the enforcement point.
        """

        evidence: list[DetectorEvidence] = []
        for inspector in self.inspectors:
            evidence.extend(inspector.inspect(content))
        return evidence

    def _publish(self, decision: SecurityDecision) -> SecurityDecision:
        self.audit.publish(decision)
        return decision

    @staticmethod
    def _latency(started: float) -> float:
        return max(round((perf_counter() - started) * 1_000, 3), 0.001)


def _asserts_another_identity(identity: str, tenant_id: str, principal: Principal) -> bool:
    """True when the body claims an identity or tenant the credential does not prove.

    A verified principal is the only authority for who is calling. Every tenant
    and resource check downstream reads the request body, so a body that
    disagrees with the credential is refused rather than reconciled.
    """

    return identity != principal.identity or tenant_id != principal.tenant_id
