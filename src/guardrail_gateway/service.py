"""Application service that composes detectors, policy, approvals, and audit."""

from __future__ import annotations

from time import perf_counter

from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.audit import AuditSink
from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import inspect_content, redact_sensitive_content
from guardrail_gateway.models import (
    ActionInspectionRequest,
    ContentInspectionRequest,
    EnforcementPoint,
    SecurityDecision,
    Verdict,
)
from guardrail_gateway.policy import action_digest, action_verdict, content_verdict


class GatewayService:
    def __init__(self, settings: Settings, approvals: ApprovalStore, audit: AuditSink) -> None:
        self.settings = settings
        self.approvals = approvals
        self.audit = audit

    def inspect_content(
        self, request: ContentInspectionRequest, point: EnforcementPoint
    ) -> SecurityDecision:
        started = perf_counter()
        if len(request.content) > self.settings.max_content_chars:
            return self._publish(
                SecurityDecision(
                    request_id=request.request_id,
                    trace_id=request.trace_id,
                    enforcement_point=point,
                    tenant_id=request.tenant_id,
                    policy_version=self.settings.policy_version,
                    verdict=Verdict.DENY,
                    reason_code="content_size_exceeded",
                    latency_ms=self._latency(started),
                )
            )

        evidence = inspect_content(request.content)
        verdict, reason = content_verdict(
            point,
            request.trust_level,
            request.source_tenant_id,
            request.tenant_id,
            evidence,
        )
        transformed = (
            redact_sensitive_content(request.content) if verdict is Verdict.TRANSFORM else None
        )
        return self._publish(
            SecurityDecision(
                request_id=request.request_id,
                trace_id=request.trace_id,
                enforcement_point=point,
                tenant_id=request.tenant_id,
                policy_version=self.settings.policy_version,
                verdict=verdict,
                reason_code=reason,
                evidence=evidence,
                transformed_content=transformed,
                latency_ms=self._latency(started),
            )
        )

    def inspect_action(self, request: ActionInspectionRequest) -> SecurityDecision:
        started = perf_counter()
        digest = action_digest(request)
        verdict, reason = action_verdict(request)
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

        return self._publish(
            SecurityDecision(
                request_id=request.request_id,
                trace_id=request.trace_id,
                enforcement_point=EnforcementPoint.ACTION,
                tenant_id=request.tenant_id,
                policy_version=self.settings.policy_version,
                verdict=verdict,
                reason_code=reason,
                action_digest=digest,
                approval_id=approval_id,
                latency_ms=self._latency(started),
            )
        )

    def _publish(self, decision: SecurityDecision) -> SecurityDecision:
        self.audit.publish(decision)
        return decision

    @staticmethod
    def _latency(started: float) -> float:
        return max(round((perf_counter() - started) * 1_000, 3), 0.001)
