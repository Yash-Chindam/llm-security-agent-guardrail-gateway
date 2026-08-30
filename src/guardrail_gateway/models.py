"""Typed API and policy data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"
    REQUIRE_APPROVAL = "require_approval"


class EnforcementPoint(StrEnum):
    INPUT = "input"
    CONTEXT = "context"
    OUTPUT = "output"
    ACTION = "action"


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class SideEffect(StrEnum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    EXTERNAL = "external"
    DESTRUCTIVE = "destructive"


class DetectorEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detector: str
    version: str
    category: str
    score: float = Field(ge=0, le=1)
    threshold: float = Field(ge=0, le=1)
    redacted_excerpt: str
    explanation: str


class ContentInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID = Field(default_factory=uuid4)
    identity: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    content: str = Field(min_length=1)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    source_tenant_id: str | None = Field(default=None, max_length=100)


class ActionInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID = Field(default_factory=uuid4)
    identity: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    resource: str = Field(min_length=1, max_length=500)
    arguments: dict[str, Any]
    side_effect: SideEffect
    approval_token: UUID | None = None


class SecurityDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    trace_id: UUID
    enforcement_point: EnforcementPoint
    tenant_id: str
    policy_version: str
    verdict: Verdict
    reason_code: str
    evidence: list[DetectorEvidence] = Field(default_factory=list)
    transformed_content: str | None = None
    action_digest: str | None = None
    approval_id: UUID | None = None
    latency_ms: float = Field(ge=0)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: UUID = Field(default_factory=uuid4)
    action_digest: str
    tenant_id: str
    requested_by: str
    reviewer: str | None = None
    rationale: str | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    issued_at: datetime
    expires_at: datetime


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rationale: str = Field(min_length=3, max_length=1000)


class HealthResponse(BaseModel):
    status: str
    policy_version: str
