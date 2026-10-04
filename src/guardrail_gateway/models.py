"""Typed API and policy data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class Classification(StrEnum):
    """Data sensitivity, in increasing order of the clearance needed to read it."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    def rank(self) -> int:
        return list(Classification).index(self)


class EntityAction(StrEnum):
    """What is done with a sensitive value of a given category."""

    ALLOW = "allow"
    REDACT = "redact"
    PSEUDONYMIZE = "pseudonymize"
    DENY = "deny"


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
    # The model the content is destined for, checked for eligibility.
    model: str | None = Field(default=None, min_length=1, max_length=200)


class Source(BaseModel):
    """A retrieved document the model was given to ground its answer on."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    content: str = Field(min_length=1, max_length=50_000)


class OutputInspectionRequest(ContentInspectionRequest):
    """Model output, with the requirements the application places on it."""

    # A JSON Schema the output must parse as and satisfy.
    output_schema: dict[str, Any] | None = None
    sources: list[Source] = Field(default_factory=list, max_length=50)
    require_citations: bool = False
    required_disclaimer: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def _disclaimer_needs_prose(self) -> Self:
        # Appending text to a structured document would break the schema.
        if self.output_schema is not None and self.required_disclaimer is not None:
            raise ValueError("required_disclaimer cannot be combined with output_schema")
        return self


class ContextDocument(BaseModel):
    """One retrieved document with the labels its authorization depends on."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:/-]+$")
    content: str = Field(min_length=1)
    # The tenant that owns the document, as recorded by the retrieval system.
    source_tenant_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    classification: Classification = Classification.INTERNAL
    # When set, only these identities or holders of these roles may read it.
    allowed_identities: list[str] | None = Field(default=None, max_length=200)
    allowed_roles: list[str] | None = Field(default=None, max_length=50)


class ContextBatchRequest(BaseModel):
    """Every document a retrieval step wants to place in front of the model."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID = Field(default_factory=uuid4)
    identity: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    documents: list[ContextDocument] = Field(min_length=1, max_length=100)


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


class SandboxResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # None when the run was killed before it could exit on its own.
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    # True when output passed the limit and the run was stopped for it.
    output_truncated: bool = False
    network: bool = False
    duration_ms: float = Field(ge=0)


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
    # Where the content may be sent, when policy constrains it.
    route: str | None = None
    latency_ms: float = Field(ge=0)


class ExecutionResponse(BaseModel):
    """The decision on a code action, and its result when it was allowed to run."""

    model_config = ConfigDict(extra="forbid")

    decision: SecurityDecision
    result: SandboxResult | None = None


class DocumentDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: str
    verdict: Verdict
    reason_code: str
    evidence: list[DetectorEvidence] = Field(default_factory=list)
    # The document as it may be shown to the model: redacted where needed and
    # wrapped as untrusted evidence. Absent when the document was refused.
    content: str | None = None


class ContextBatchDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    trace_id: UUID
    enforcement_point: EnforcementPoint = EnforcementPoint.CONTEXT
    tenant_id: str
    policy_version: str
    verdict: Verdict
    reason_code: str
    documents: list[DocumentDecision] = Field(default_factory=list)
    admitted: int = Field(ge=0)
    latency_ms: float = Field(ge=0)


class PseudonymRestoreRequest(BaseModel):
    """Content whose pseudonyms should be turned back into their values."""

    model_config = ConfigDict(extra="forbid")

    identity: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    # The trace the pseudonyms were issued under; another trace's are unknown.
    trace_id: UUID
    content: str = Field(min_length=1, max_length=1_000_000)


class PseudonymRestoreResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    restored: int = Field(ge=0)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
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


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Disposition(StrEnum):
    """What a reviewer concluded the related decisions were."""

    UNDETERMINED = "undetermined"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"


class IncidentCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: UUID = Field(default_factory=uuid4)
    tenant_id: str
    title: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    disposition: Disposition = Disposition.UNDETERMINED
    decision_ids: list[UUID] = Field(default_factory=list)
    trace_ids: list[UUID] = Field(default_factory=list)
    remediation: str | None = None
    opened_by: str
    created_at: datetime
    updated_at: datetime


class IncidentOpenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=3, max_length=200)
    severity: Severity
    decision_ids: list[UUID] = Field(min_length=1, max_length=100)


class IncidentUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: IncidentStatus | None = None
    disposition: Disposition | None = None
    remediation: str | None = Field(default=None, min_length=1, max_length=5_000)

    @model_validator(mode="after")
    def _changes_something(self) -> Self:
        if self.status is None and self.disposition is None and self.remediation is None:
            raise ValueError("an update must change at least one field")
        return self


class HealthResponse(BaseModel):
    status: str
    policy_version: str
    identity_verification: str = "configured"
    audit: str = "durable"
    stores: str = "available"
    policy: str = "available"
