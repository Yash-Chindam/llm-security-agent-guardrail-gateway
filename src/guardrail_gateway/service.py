"""Application service that composes detectors, policy, approvals, and audit.

Section 15 of the design specification fixes the behaviour when a security
dependency fails. Each dependency is reached through a port so its failure is
an explicit condition handled here, never an unhandled error that could leave
a request half-enforced.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import wraps
from time import monotonic, perf_counter
from typing import Concatenate, ParamSpec, TypeVar
from uuid import UUID

from opentelemetry import trace

from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.audit import AuditSink
from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import (
    CanaryInspector,
    ContentInspector,
    DetectorUnavailableError,
    DeterministicInspector,
    Finding,
)
from guardrail_gateway.identity import Principal
from guardrail_gateway.incidents import DecisionLog, IncidentStore
from guardrail_gateway.limits import ExecutionBudget, RateLimiter, ViolationHistory
from guardrail_gateway.metrics import GatewayMetrics
from guardrail_gateway.models import (
    ActionInspectionRequest,
    ContentInspectionRequest,
    ContextBatchDecision,
    ContextBatchRequest,
    ContextDocument,
    DetectorEvidence,
    DocumentDecision,
    EnforcementPoint,
    OutputInspectionRequest,
    PseudonymRestoreRequest,
    PseudonymRestoreResponse,
    SecurityDecision,
    Severity,
    SideEffect,
    TrustLevel,
    Verdict,
)
from guardrail_gateway.output import OutputPolicyConfig, output_verdict
from guardrail_gateway.policy import (
    LocalPolicyEngine,
    PolicyEngine,
    PolicyEngineUnavailableError,
    action_digest,
)
from guardrail_gateway.sensitive import (
    InMemoryPseudonymVault,
    PseudonymVault,
    action_resolver,
    transform,
)
from guardrail_gateway.tracing import record_decision, tracer_for

_P = ParamSpec("_P")
_R = TypeVar("_R")

# Effects that change nothing outside the gateway, and so may continue under
# the built-in policy while the policy decision point is unreachable.
_READ_ONLY_EFFECTS = frozenset({SideEffect.NONE, SideEffect.READ})
# Denials that show an identity is probing the detectors for a bypass.
_VIOLATION_REASONS = frozenset(
    {"prompt_injection_detected", "obfuscated_content_detected", "embedded_action_detected"}
)
_LOCAL_ONLY = "local_only"
_CANARY_INCIDENT = "Canary secret observed"
_SYSTEM_ACTOR = "guardrail-gateway"
# A document that names the envelope could close it early and continue as
# if it were outside, so the tag is made inert inside admitted content.
_ENVELOPE_TAG = re.compile(r"<(/?\s*untrusted_evidence)", re.IGNORECASE)


def _traced(
    name: str,
) -> Callable[
    [Callable[Concatenate[GatewayService, _P], _R]],
    Callable[Concatenate[GatewayService, _P], _R],
]:
    """Run an enforcement call inside one span, so its detectors nest under it."""

    def wrap(
        method: Callable[Concatenate[GatewayService, _P], _R],
    ) -> Callable[Concatenate[GatewayService, _P], _R]:
        @wraps(method)
        def traced(self: GatewayService, /, *args: _P.args, **kwargs: _P.kwargs) -> _R:
            with self._tracer.start_as_current_span(name):
                return method(self, *args, **kwargs)

        return traced

    return wrap


class GatewayService:
    def __init__(
        self,
        settings: Settings,
        approvals: ApprovalStore,
        audit: AuditSink,
        policy: PolicyEngine | None = None,
        inspectors: tuple[ContentInspector, ...] | None = None,
        clock: Callable[[], float] = monotonic,
        vault: PseudonymVault | None = None,
        tracer_provider: trace.TracerProvider | None = None,
    ) -> None:
        self.settings = settings
        self._tracer = tracer_for(tracer_provider)
        self.approvals = approvals
        self.audit = audit
        self.policy: PolicyEngine = policy or LocalPolicyEngine(settings)
        self.inspectors: tuple[ContentInspector, ...] = inspectors or (DeterministicInspector(),)
        if settings.canary_secrets:
            canaries = tuple(value.get_secret_value() for value in settings.canary_secrets)
            self.inspectors = (*self.inspectors, CanaryInspector(canaries))
        self.vault: PseudonymVault = vault or InMemoryPseudonymVault(
            settings.pseudonym_ttl_seconds, clock=clock
        )
        self._restricted_policy = LocalPolicyEngine(settings)
        self._identity_quota = RateLimiter(settings.identity_requests_per_minute, clock=clock)
        self._tenant_quota = RateLimiter(settings.tenant_requests_per_minute, clock=clock)
        self._budget = ExecutionBudget(settings.max_actions_per_trace)
        self._violations = ViolationHistory(
            settings.violation_lockout_threshold,
            settings.violation_window_seconds,
            clock=clock,
        )
        self._output_policy = OutputPolicyConfig.from_settings(settings)
        self.metrics = GatewayMetrics()
        self.decisions = DecisionLog(settings.decision_log_size)
        self.incidents = IncidentStore(settings.incident_store_size)

    @_traced("guardrail.inspect_content")
    def inspect_content(
        self,
        request: ContentInspectionRequest,
        point: EnforcementPoint,
        principal: Principal,
    ) -> SecurityDecision:
        started = perf_counter()
        offender = (principal.tenant_id, principal.identity)

        def decide(
            verdict: Verdict,
            reason: str,
            evidence: list[DetectorEvidence] | None = None,
            transformed: str | None = None,
            route: str | None = None,
        ) -> SecurityDecision:
            if reason in _VIOLATION_REASONS:
                self._violations.record(offender)
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
                    route=route,
                    latency_ms=self._latency(started),
                )
            )

        if _asserts_another_identity(request.identity, request.tenant_id, principal):
            return decide(Verdict.DENY, "identity_assertion_mismatch")
        if not self.audit.accepting():
            return decide(Verdict.DENY, "audit_durability_unavailable")
        if not self._within_quota(principal):
            return decide(Verdict.DENY, "quota_exceeded")
        if self._violations.locked(offender):
            return decide(Verdict.DENY, "repeated_policy_violations")
        if not self._model_eligible(request.model):
            return decide(Verdict.DENY, "model_not_eligible")
        if len(request.content) > self.settings.max_content_chars:
            return decide(Verdict.DENY, "content_size_exceeded")

        verdict, reason, findings = self._judge(
            point,
            request.trust_level,
            request.source_tenant_id,
            request.tenant_id,
            request.content,
        )
        evidence = [finding.evidence for finding in findings]
        if verdict is Verdict.DENY:
            return decide(verdict, reason, evidence)

        if verdict is Verdict.TRANSFORM and request.model in self.settings.local_only_models:
            # Section 8.1: sensitive content may reach a model that runs inside
            # the trusted boundary intact, and nowhere else.
            return decide(
                Verdict.ALLOW, "sensitive_content_local_only", evidence, None, _LOCAL_ONLY
            )

        transformed = (
            self._transformed(request.content, findings, principal.tenant_id, request.trace_id)
            if verdict is Verdict.TRANSFORM
            else None
        )
        if verdict is Verdict.ALLOW and isinstance(request, OutputInspectionRequest):
            verdict, output_reason, transformed = output_verdict(request, self._output_policy)
            if verdict is not Verdict.ALLOW or output_reason != "policy_allow":
                reason = output_reason
        return decide(verdict, reason, evidence, transformed)

    @_traced("guardrail.inspect_context_batch")
    def inspect_context_batch(
        self, request: ContextBatchRequest, principal: Principal
    ) -> ContextBatchDecision:
        """Authorize and inspect each retrieved document on its own.

        Section 8.2 requires authorization for every document. A batch is
        therefore never accepted or refused as a whole: each document stands
        or falls on its own labels, and what survives is returned wrapped as
        untrusted evidence so it cannot pass for an instruction.
        """

        started = perf_counter()
        offender = (principal.tenant_id, principal.identity)

        def conclude(
            verdict: Verdict, reason: str, documents: list[DocumentDecision] | None = None
        ) -> ContextBatchDecision:
            results = documents or []
            decision = ContextBatchDecision(
                request_id=request.request_id,
                trace_id=request.trace_id,
                tenant_id=principal.tenant_id,
                policy_version=self.settings.policy_version,
                verdict=verdict,
                reason_code=reason,
                documents=results,
                admitted=sum(1 for item in results if item.content is not None),
                latency_ms=self._latency(started),
            )
            self._publish(
                SecurityDecision(
                    decision_id=decision.decision_id,
                    request_id=request.request_id,
                    trace_id=request.trace_id,
                    enforcement_point=EnforcementPoint.CONTEXT,
                    tenant_id=principal.tenant_id,
                    policy_version=self.settings.policy_version,
                    verdict=verdict,
                    reason_code=reason,
                    latency_ms=decision.latency_ms,
                )
            )
            return decision

        if _asserts_another_identity(request.identity, request.tenant_id, principal):
            return conclude(Verdict.DENY, "identity_assertion_mismatch")
        if not self.audit.accepting():
            return conclude(Verdict.DENY, "audit_durability_unavailable")
        if not self._within_quota(principal):
            return conclude(Verdict.DENY, "quota_exceeded")
        if self._violations.locked(offender):
            return conclude(Verdict.DENY, "repeated_policy_violations")

        remaining = self.settings.max_context_chars
        results: list[DocumentDecision] = []
        for document in request.documents:
            result = self._judge_document(document, principal, remaining, request.trace_id)
            if result.reason_code in _VIOLATION_REASONS:
                self._violations.record(offender)
            if result.content is not None:
                remaining -= len(document.content)
            # Each document is attributable on its own, not only the batch.
            self._publish(
                SecurityDecision(
                    request_id=request.request_id,
                    trace_id=request.trace_id,
                    enforcement_point=EnforcementPoint.CONTEXT,
                    tenant_id=principal.tenant_id,
                    policy_version=self.settings.policy_version,
                    verdict=result.verdict,
                    reason_code=result.reason_code,
                    evidence=result.evidence,
                    latency_ms=self._latency(started),
                )
            )
            results.append(result)

        if not any(item.content is not None for item in results):
            return conclude(Verdict.DENY, "no_authorized_context", results)
        if all(item.verdict is Verdict.ALLOW for item in results):
            return conclude(Verdict.ALLOW, "policy_allow", results)
        return conclude(Verdict.TRANSFORM, "context_filtered", results)

    def _judge_document(
        self, document: ContextDocument, principal: Principal, remaining: int, trace_id: UUID
    ) -> DocumentDecision:
        def refuse(reason: str, evidence: list[DetectorEvidence] | None = None) -> DocumentDecision:
            return DocumentDecision(
                document_id=document.id,
                verdict=Verdict.DENY,
                reason_code=reason,
                evidence=evidence or [],
            )

        if document.source_tenant_id != principal.tenant_id:
            return refuse("cross_tenant_context")
        if not _may_read(document, principal):
            return refuse("document_not_authorized")
        if len(document.content) > self.settings.max_content_chars:
            return refuse("content_size_exceeded")
        if len(document.content) > remaining:
            return refuse("context_budget_exceeded")

        verdict, reason, findings = self._judge(
            EnforcementPoint.CONTEXT,
            document.trust_level,
            document.source_tenant_id,
            principal.tenant_id,
            document.content,
        )
        evidence = [finding.evidence for finding in findings]
        if verdict is Verdict.DENY:
            return refuse(reason, evidence)

        content = (
            self._transformed(document.content, findings, principal.tenant_id, trace_id)
            if verdict is Verdict.TRANSFORM
            else document.content
        )
        return DocumentDecision(
            document_id=document.id,
            verdict=verdict,
            reason_code=reason,
            evidence=evidence,
            content=_as_untrusted_evidence(document, content),
        )

    def _judge(
        self,
        point: EnforcementPoint,
        trust_level: TrustLevel,
        source_tenant_id: str | None,
        tenant_id: str,
        content: str,
    ) -> tuple[Verdict, str, list[Finding]]:
        """Inspect content and decide it, applying section 15 to each dependency."""

        try:
            findings = self._findings(content)
        except DetectorUnavailableError:
            # Uninspected content may carry anything, so it does not continue.
            return Verdict.DENY, "content_inspection_unavailable", []
        evidence = [finding.evidence for finding in findings]

        try:
            verdict, reason = self.policy.content_verdict(
                point, trust_level, source_tenant_id, tenant_id, evidence
            )
        except PolicyEngineUnavailableError:
            if not self.settings.restricted_read_only_mode:
                return Verdict.DENY, "policy_engine_unavailable", findings
            verdict, reason = self._restricted_policy.content_verdict(
                point, trust_level, source_tenant_id, tenant_id, evidence
            )
            if verdict is Verdict.ALLOW:
                reason = "restricted_read_only_mode"
        return verdict, reason, findings

    @_traced("guardrail.inspect_action")
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
        if not self._within_quota(principal):
            return decide(Verdict.DENY, "quota_exceeded")

        digest = action_digest(request)
        # Counted before policy runs, so a loop of refused actions spends the
        # budget exactly as a loop of permitted ones does.
        if not self._budget.consume((principal.tenant_id, request.trace_id)):
            return decide(Verdict.DENY, "execution_budget_exceeded", digest)
        try:
            verdict, reason = self.policy.action_verdict(request, principal.roles)
        except PolicyEngineUnavailableError:
            # A side effect is never authorized by a fallback: without the
            # policy decision point it fails closed, whatever mode is enabled.
            restricted = (
                self.settings.restricted_read_only_mode
                and request.side_effect in _READ_ONLY_EFFECTS
            )
            if not restricted:
                return decide(Verdict.DENY, "policy_engine_unavailable", digest)
            verdict, reason = self._restricted_policy.action_verdict(request, principal.roles)
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

    def _model_eligible(self, model: str | None) -> bool:
        """A named model must be one the deployment permits, when it restricts them."""

        permitted = self.settings.eligible_models + self.settings.local_only_models
        return model is None or not permitted or model in permitted

    def _within_quota(self, principal: Principal) -> bool:
        """Count the request against its identity, then against its tenant.

        The identity is checked first so one noisy caller is stopped by its own
        limit before it can spend the quota its whole tenant shares.
        """

        if not self._identity_quota.allow((principal.tenant_id, principal.identity)):
            return False
        return self._tenant_quota.allow(principal.tenant_id)

    def _findings(self, content: str) -> list[Finding]:
        """Union every inspector's findings.

        When detectors disagree, the union is the conservative reading section
        15 asks for: one detector's finding is never outvoted by another's
        silence, and policy then weighs it against the enforcement point.
        """

        findings: list[Finding] = []
        for inspector in self.inspectors:
            detector = type(inspector).__name__
            started = perf_counter()
            with self._tracer.start_as_current_span(
                "guardrail.detector", attributes={"guardrail.detector": detector}
            ):
                try:
                    findings.extend(inspector.inspect(content))
                finally:
                    # A detector that failed still took time, and a slow
                    # failure is exactly what the latency metric must show.
                    self.metrics.observe_detector(detector, perf_counter() - started)
        return findings

    def _transformed(
        self, content: str, findings: list[Finding], tenant_id: str, trace_id: UUID
    ) -> str:
        """Apply the tenant's rule to each sensitive value that was located."""

        scope = (tenant_id, trace_id)
        return transform(
            content,
            findings,
            action_resolver(self.settings, tenant_id),
            lambda category, value: self.vault.tokenize(scope, category, value),
        )

    def restore_pseudonyms(
        self, request: PseudonymRestoreRequest, principal: Principal
    ) -> PseudonymRestoreResponse | None:
        """Turn a trace's pseudonyms back into values, for the tenant that owns them.

        Returns None when the body claims an identity the credential does not
        prove. The scope is the caller's proven tenant, so one tenant can never
        resolve another's pseudonyms even with the trace identifier in hand.
        """

        if _asserts_another_identity(request.identity, request.tenant_id, principal):
            self.audit.publish_rejection("identity_assertion_mismatch", "/v1/pseudonyms/restore")
            return None
        content, restored = self.vault.restore(
            (principal.tenant_id, request.trace_id), request.content
        )
        self.audit.publish_operation(
            "pseudonyms_restored", principal.tenant_id, str(request.trace_id), restored
        )
        return PseudonymRestoreResponse(content=content, restored=restored)

    def _publish(self, decision: SecurityDecision) -> SecurityDecision:
        self.audit.publish(decision)
        self.decisions.record(decision)
        self.metrics.observe(decision)
        record_decision(decision)
        if decision.reason_code == "canary_leak_detected":
            self._open_canary_incident(decision)
        return decision

    def _open_canary_incident(self, decision: SecurityDecision) -> None:
        """A canary sighting is a leak by construction, so it opens its own case.

        Further sightings in the same trace join the open case instead of
        opening one each, so a single leak does not bury the queue.
        """

        existing = self.incidents.open_for_trace(
            decision.trace_id, decision.tenant_id, _CANARY_INCIDENT
        )
        if existing is not None:
            self.incidents.attach(existing.incident_id, decision)
            return
        self.incidents.open(
            decision.tenant_id, _CANARY_INCIDENT, Severity.CRITICAL, _SYSTEM_ACTOR, [decision]
        )

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


def _may_read(document: ContextDocument, principal: Principal) -> bool:
    """Whether the caller's clearance and the document's access list both permit it."""

    if document.classification.rank() > principal.clearance.rank():
        return False
    if document.allowed_identities is None and document.allowed_roles is None:
        return True
    if principal.identity in (document.allowed_identities or ()):
        return True
    held = {role.value for role in principal.roles}
    return bool(held & set(document.allowed_roles or ()))


def _as_untrusted_evidence(document: ContextDocument, content: str) -> str:
    """Label a document so the model reads it as evidence, never as instruction."""

    inert = _ENVELOPE_TAG.sub(r"&lt;\1", content)
    return (
        f'<untrusted_evidence id="{document.id}" source_tenant="{document.source_tenant_id}" '
        f'trust="{document.trust_level.value}">\n{inert}\n</untrusted_evidence>'
    )
