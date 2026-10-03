"""FastAPI application factory and public enforcement endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response

from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.audit import AuditSink, AuditTransport
from guardrail_gateway.config import Settings, get_settings
from guardrail_gateway.detectors import ContentInspector, DeterministicInspector
from guardrail_gateway.identity import (
    AuthenticationFailure,
    CredentialError,
    IdentityVerifier,
    Principal,
    Role,
)
from guardrail_gateway.metrics import CONTENT_TYPE
from guardrail_gateway.models import (
    ActionInspectionRequest,
    ApprovalDecisionRequest,
    ApprovalRecord,
    ApprovalStatus,
    ContentInspectionRequest,
    ContextBatchDecision,
    ContextBatchRequest,
    EnforcementPoint,
    HealthResponse,
    IncidentCase,
    IncidentOpenRequest,
    IncidentUpdateRequest,
    OutputInspectionRequest,
    PseudonymRestoreRequest,
    PseudonymRestoreResponse,
    SecurityDecision,
)
from guardrail_gateway.policy import PolicyEngine
from guardrail_gateway.presidio import PresidioInspector
from guardrail_gateway.sensitive import PseudonymVault
from guardrail_gateway.service import GatewayService


def get_gateway_service(request: Request) -> GatewayService:
    """Resolve the service from the current application instance."""

    return request.app.state.gateway_service  # type: ignore[no-any-return]


def authenticated_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    """Verify the caller's credential before any enforcement logic runs."""

    verifier: IdentityVerifier = request.app.state.identity_verifier
    service: GatewayService = request.app.state.gateway_service
    try:
        return verifier.verify(authorization)
    except CredentialError as error:
        service.audit.publish_rejection(error.failure.value, request.url.path)
        service.metrics.observe_rejection(error.failure.value)
        # A missing verifier is the deployment's failure, not the caller's, and
        # section 15 requires that condition to be deterministic rather than
        # degrading into unauthenticated access.
        code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if error.failure is AuthenticationFailure.UNAVAILABLE
            else status.HTTP_401_UNAUTHORIZED
        )
        raise HTTPException(
            status_code=code,
            detail=error.failure.value,
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


GatewayDependency = Annotated[GatewayService, Depends(get_gateway_service)]
PrincipalDependency = Annotated[Principal, Depends(authenticated_principal)]


def create_app(
    settings: Settings | None = None,
    *,
    policy: PolicyEngine | None = None,
    inspectors: tuple[ContentInspector, ...] | None = None,
    audit_transport: AuditTransport | None = None,
    vault: PseudonymVault | None = None,
) -> FastAPI:
    """Build the gateway; the keyword adapters replace the in-process defaults."""

    runtime_settings = settings or get_settings()
    approvals = ApprovalStore(runtime_settings.approval_ttl_seconds)
    audit = AuditSink(
        runtime_settings.audit_buffer_size,
        transport=audit_transport,
        mandatory=runtime_settings.audit_mandatory,
    )
    if inspectors is None and runtime_settings.presidio_url is not None:
        inspectors = (
            DeterministicInspector(),
            PresidioInspector(
                runtime_settings.presidio_url,
                runtime_settings.presidio_timeout_seconds,
                runtime_settings.presidio_score_threshold,
            ),
        )
    service = GatewayService(runtime_settings, approvals, audit, policy, inspectors, vault=vault)
    verifier = IdentityVerifier(runtime_settings)

    application = FastAPI(
        title="LLM Security and Agent Guardrail Gateway",
        version="0.10.0",
        description="Deterministic security enforcement for LLM and agent boundaries.",
    )
    application.state.gateway_service = service
    application.state.identity_verifier = verifier

    @application.get("/health/live", response_model=HealthResponse, tags=["health"])
    def live() -> HealthResponse:
        return HealthResponse(
            status="ok",
            policy_version=runtime_settings.policy_version,
            identity_verification=_verification_state(verifier),
            audit=audit.state(),
        )

    @application.get("/health/ready", response_model=HealthResponse, tags=["health"])
    def ready() -> JSONResponse:
        # Not ready while no credential can be verified or no decision can be
        # audited: the gateway is running but every enforcement request will be
        # refused, and a load balancer should see that rather than send traffic
        # into a closed gate.
        audit_state = audit.state()
        serving = verifier.configured and audit_state != "blocked"
        body = HealthResponse(
            status="ready" if serving else "not_ready",
            policy_version=runtime_settings.policy_version,
            identity_verification=_verification_state(verifier),
            audit=audit_state,
        )
        code = status.HTTP_200_OK if serving else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(status_code=code, content=body.model_dump())

    @application.post("/v1/inspect/input", response_model=SecurityDecision, tags=["inspection"])
    def inspect_input(
        request: ContentInspectionRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> SecurityDecision:
        return gateway.inspect_content(request, EnforcementPoint.INPUT, principal)

    @application.post("/v1/inspect/context", response_model=SecurityDecision, tags=["inspection"])
    def inspect_context(
        request: ContentInspectionRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> SecurityDecision:
        return gateway.inspect_content(request, EnforcementPoint.CONTEXT, principal)

    @application.post(
        "/v1/inspect/context/batch", response_model=ContextBatchDecision, tags=["inspection"]
    )
    def inspect_context_batch(
        request: ContextBatchRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> ContextBatchDecision:
        return gateway.inspect_context_batch(request, principal)

    @application.post("/v1/inspect/output", response_model=SecurityDecision, tags=["inspection"])
    def inspect_output(
        request: OutputInspectionRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> SecurityDecision:
        return gateway.inspect_content(request, EnforcementPoint.OUTPUT, principal)

    @application.post("/v1/inspect/action", response_model=SecurityDecision, tags=["inspection"])
    def inspect_action(
        request: ActionInspectionRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> SecurityDecision:
        return gateway.inspect_action(request, principal)

    @application.post(
        "/v1/pseudonyms/restore", response_model=PseudonymRestoreResponse, tags=["pseudonyms"]
    )
    def restore_pseudonyms(
        request: PseudonymRestoreRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> PseudonymRestoreResponse:
        restored = gateway.restore_pseudonyms(request, principal)
        if restored is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="identity_assertion_mismatch"
            )
        return restored

    @application.get(
        "/v1/approvals/{approval_id}", response_model=ApprovalRecord, tags=["approval"]
    )
    def get_approval(
        approval_id: UUID,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> ApprovalRecord:
        record = gateway.approvals.get(approval_id)
        # Another tenant's approval is reported as missing rather than
        # forbidden, so the endpoint cannot be used to confirm it exists.
        if record is None or record.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
        return record

    def adjudicable(approval_id: UUID, gateway: GatewayService, principal: Principal) -> None:
        """Refuse an adjudication the caller is not entitled to make."""

        if not principal.has_role(Role.REVIEWER):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="reviewer_role_required",
            )

        record = gateway.approvals.get(approval_id)
        if record is None or record.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")

        # Separation of duties: the identity that proposed the action cannot be
        # the identity that adjudicates it, whatever roles it holds.
        if record.requested_by == principal.identity:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="self_approval_forbidden",
            )

    def adjudicated(record: ApprovalRecord | None, outcome: ApprovalStatus) -> ApprovalRecord:
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
        if record.status is not outcome:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Approval is {record.status.value}",
            )
        return record

    @application.post(
        "/v1/approvals/{approval_id}/approve",
        response_model=ApprovalRecord,
        tags=["approval"],
    )
    def approve_action(
        approval_id: UUID,
        decision: ApprovalDecisionRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> ApprovalRecord:
        adjudicable(approval_id, gateway, principal)
        approved = gateway.approvals.approve(approval_id, principal.identity, decision.rationale)
        return adjudicated(approved, ApprovalStatus.APPROVED)

    @application.post(
        "/v1/approvals/{approval_id}/reject",
        response_model=ApprovalRecord,
        tags=["approval"],
    )
    def reject_action(
        approval_id: UUID,
        decision: ApprovalDecisionRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> ApprovalRecord:
        adjudicable(approval_id, gateway, principal)
        rejected = gateway.approvals.reject(approval_id, principal.identity, decision.rationale)
        return adjudicated(rejected, ApprovalStatus.REJECTED)

    def require_any(principal: Principal, *roles: Role) -> None:
        if not any(principal.has_role(role) for role in roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="role_required")

    @application.get("/v1/decisions/{decision_id}", response_model=SecurityDecision, tags=["audit"])
    def get_decision(
        decision_id: UUID, gateway: GatewayDependency, principal: PrincipalDependency
    ) -> SecurityDecision:
        require_any(principal, Role.AUDITOR, Role.REVIEWER)
        decision = gateway.decisions.get(decision_id, principal.tenant_id)
        if decision is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")
        return decision

    @application.get("/v1/decisions", response_model=list[SecurityDecision], tags=["audit"])
    def list_decisions(
        trace_id: UUID, gateway: GatewayDependency, principal: PrincipalDependency
    ) -> list[SecurityDecision]:
        require_any(principal, Role.AUDITOR, Role.REVIEWER)
        return gateway.decisions.for_trace(trace_id, principal.tenant_id)

    @application.post(
        "/v1/incidents",
        response_model=IncidentCase,
        status_code=status.HTTP_201_CREATED,
        tags=["incidents"],
    )
    def open_incident(
        request: IncidentOpenRequest, gateway: GatewayDependency, principal: PrincipalDependency
    ) -> IncidentCase:
        require_any(principal, Role.REVIEWER)
        decisions = [
            gateway.decisions.get(decision_id, principal.tenant_id)
            for decision_id in request.decision_ids
        ]
        known = [decision for decision in decisions if decision is not None]
        # A case may only cite decisions the caller's tenant can actually read,
        # so it cannot be used to probe for another tenant's decision ids.
        if len(known) != len(decisions):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")
        return gateway.incidents.open(
            principal.tenant_id, request.title, request.severity, principal.identity, known
        )

    @application.get("/v1/incidents", response_model=list[IncidentCase], tags=["incidents"])
    def list_incidents(
        gateway: GatewayDependency, principal: PrincipalDependency
    ) -> list[IncidentCase]:
        require_any(principal, Role.AUDITOR, Role.REVIEWER)
        return gateway.incidents.list(principal.tenant_id)

    @application.get("/v1/incidents/{incident_id}", response_model=IncidentCase, tags=["incidents"])
    def get_incident(
        incident_id: UUID, gateway: GatewayDependency, principal: PrincipalDependency
    ) -> IncidentCase:
        require_any(principal, Role.AUDITOR, Role.REVIEWER)
        incident = gateway.incidents.get(incident_id, principal.tenant_id)
        if incident is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        return incident

    @application.patch(
        "/v1/incidents/{incident_id}", response_model=IncidentCase, tags=["incidents"]
    )
    def update_incident(
        incident_id: UUID,
        request: IncidentUpdateRequest,
        gateway: GatewayDependency,
        principal: PrincipalDependency,
    ) -> IncidentCase:
        require_any(principal, Role.REVIEWER)
        incident = gateway.incidents.update(
            incident_id,
            principal.tenant_id,
            request.status,
            request.disposition,
            request.remediation,
        )
        if incident is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        return incident

    @application.get("/metrics", tags=["health"], include_in_schema=False)
    def metrics() -> Response:
        body = service.metrics.render(
            approvals.counts, audit.pending, audit.dropped, service.incidents.open_count()
        )
        return Response(content=body, media_type=CONTENT_TYPE)

    return application


def _verification_state(verifier: IdentityVerifier) -> str:
    return "configured" if verifier.configured else "unavailable"


app = create_app()
