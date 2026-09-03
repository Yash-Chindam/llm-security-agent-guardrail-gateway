"""FastAPI application factory and public enforcement endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status

from guardrail_gateway.approvals import ApprovalStore
from guardrail_gateway.audit import AuditSink
from guardrail_gateway.config import Settings, get_settings
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
from guardrail_gateway.service import GatewayService


def get_gateway_service(request: Request) -> GatewayService:
    """Resolve the service from the current application instance."""

    return request.app.state.gateway_service  # type: ignore[no-any-return]


GatewayDependency = Annotated[GatewayService, Depends(get_gateway_service)]


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()
    approvals = ApprovalStore(runtime_settings.approval_ttl_seconds)
    audit = AuditSink(runtime_settings.audit_buffer_size)
    service = GatewayService(runtime_settings, approvals, audit)

    application = FastAPI(
        title="LLM Security and Agent Guardrail Gateway",
        version="0.2.0",
        description="Deterministic security enforcement for LLM and agent boundaries.",
    )
    application.state.gateway_service = service

    @application.get("/health/live", response_model=HealthResponse, tags=["health"])
    def live() -> HealthResponse:
        return HealthResponse(status="ok", policy_version=runtime_settings.policy_version)

    @application.get("/health/ready", response_model=HealthResponse, tags=["health"])
    def ready() -> HealthResponse:
        return HealthResponse(status="ready", policy_version=runtime_settings.policy_version)

    @application.post("/v1/inspect/input", response_model=SecurityDecision, tags=["inspection"])
    def inspect_input(
        request: ContentInspectionRequest, gateway: GatewayDependency
    ) -> SecurityDecision:
        return gateway.inspect_content(request, EnforcementPoint.INPUT)

    @application.post("/v1/inspect/context", response_model=SecurityDecision, tags=["inspection"])
    def inspect_context(
        request: ContentInspectionRequest, gateway: GatewayDependency
    ) -> SecurityDecision:
        return gateway.inspect_content(request, EnforcementPoint.CONTEXT)

    @application.post("/v1/inspect/output", response_model=SecurityDecision, tags=["inspection"])
    def inspect_output(
        request: ContentInspectionRequest, gateway: GatewayDependency
    ) -> SecurityDecision:
        return gateway.inspect_content(request, EnforcementPoint.OUTPUT)

    @application.post("/v1/inspect/action", response_model=SecurityDecision, tags=["inspection"])
    def inspect_action(
        request: ActionInspectionRequest, gateway: GatewayDependency
    ) -> SecurityDecision:
        return gateway.inspect_action(request)

    @application.get(
        "/v1/approvals/{approval_id}", response_model=ApprovalRecord, tags=["approval"]
    )
    def get_approval(approval_id: UUID, gateway: GatewayDependency) -> ApprovalRecord:
        record = gateway.approvals.get(approval_id)
        if record is None:
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
        reviewer_id: Annotated[str | None, Header(alias="X-Reviewer-Id")] = None,
    ) -> ApprovalRecord:
        if not reviewer_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authenticated reviewer identity required",
            )
        record = gateway.approvals.approve(approval_id, reviewer_id, decision.rationale)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
        if record.status is not ApprovalStatus.APPROVED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Approval is {record.status.value}",
            )
        return record

    return application


app = create_app()
