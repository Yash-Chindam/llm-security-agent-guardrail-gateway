"""FastAPI application factory and public enforcement endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.audit import AuditSink, AuditTransport
from guardrail_gateway.config import Settings, get_settings
from guardrail_gateway.detectors import ContentInspector
from guardrail_gateway.identity import (
    AuthenticationFailure,
    CredentialError,
    IdentityVerifier,
    Principal,
    Role,
)
from guardrail_gateway.models import (
    ActionInspectionRequest,
    ApprovalDecisionRequest,
    ApprovalRecord,
    ApprovalStatus,
    ContentInspectionRequest,
    EnforcementPoint,
    HealthResponse,
    SecurityDecision,
)
from guardrail_gateway.policy import PolicyEngine
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
) -> FastAPI:
    """Build the gateway; the keyword adapters replace the in-process defaults."""

    runtime_settings = settings or get_settings()
    approvals = ApprovalStore(runtime_settings.approval_ttl_seconds)
    audit = AuditSink(
        runtime_settings.audit_buffer_size,
        transport=audit_transport,
        mandatory=runtime_settings.audit_mandatory,
    )
    service = GatewayService(runtime_settings, approvals, audit, policy, inspectors)
    verifier = IdentityVerifier(runtime_settings)

    application = FastAPI(
        title="LLM Security and Agent Guardrail Gateway",
        version="0.6.0",
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

    @application.post("/v1/inspect/output", response_model=SecurityDecision, tags=["inspection"])
    def inspect_output(
        request: ContentInspectionRequest,
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

        approved = gateway.approvals.approve(approval_id, principal.identity, decision.rationale)
        if approved is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
        if approved.status is not ApprovalStatus.APPROVED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Approval is {approved.status.value}",
            )
        return approved

    return application


def _verification_state(verifier: IdentityVerifier) -> str:
    return "configured" if verifier.configured else "unavailable"


app = create_app()
