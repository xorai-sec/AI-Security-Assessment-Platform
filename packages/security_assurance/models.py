from __future__ import annotations

from datetime import datetime, timezone

UTC = timezone.utc
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class EnvironmentType(str, Enum):
    local_lab = "local_lab"
    pre_production = "pre_production"
    internal_assessment = "internal_assessment"
    production = "production"


class FindingStatus(str, Enum):
    raw_alert = "raw_alert"
    candidate = "candidate"
    confirmed = "confirmed"
    false_positive = "false_positive"
    needs_human_review = "needs_human_review"


class Severity(str, Enum):
    info = "Info"
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class Organization(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ORG"))
    name: str
    industry: str
    country_or_region: str
    business_context: str
    risk_appetite: str = "moderate"
    data_classifications: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AISystem(BaseModel):
    id: str = Field(default_factory=lambda: new_id("AIS"))
    organization_id: str
    name: str
    description: str
    business_purpose: str
    system_owner: str
    deployment_status: str
    model_provider: str
    model_name: str
    model_endpoint: str
    system_type: str
    rag_enabled: bool
    memory_enabled: bool
    tool_use_enabled: bool
    human_oversight_description: str
    data_sources: list[str]
    user_roles: list[str]
    critical_actions: list[str]
    architecture_metadata: dict[str, Any] = Field(default_factory=dict)


class AssessmentScope(BaseModel):
    id: str = Field(default_factory=lambda: new_id("SCOPE"))
    assessment_name: str
    organization_name: str
    target_name: str
    target_url: str
    environment_type: EnvironmentType
    system_owner: str
    authorized_tester: str
    testing_start: datetime
    testing_end: datetime
    allowed_attack_categories: list[str]
    disallowed_activities: list[str]
    data_classification: str
    written_authorization_confirmed: bool
    production: bool = False
    rate_limit_seconds: float = 1.0
    max_requests: int = 100
    max_duration_seconds: int = 1800
    emergency_stop_enabled: bool = True

    def validate_authorized(self) -> None:
        if not self.written_authorization_confirmed:
            raise ValueError("Written authorization must be confirmed before assessment")
        if self.production:
            raise ValueError("Production targets are disabled by default for this demo")
        if self.max_requests <= 0:
            raise ValueError("max_requests must be positive")


class CampaignSpec(BaseModel):
    id: str = Field(default_factory=lambda: new_id("CMP"))
    assessment_id: str
    framework: str
    attack_category: str
    objective: str
    strategy: str
    status: str = "planned"
    request_budget: int = 10
    max_turns: int = 1


class AttackExecution(BaseModel):
    id: str = Field(default_factory=lambda: new_id("EXEC"))
    campaign_id: str
    framework: str
    framework_version: str
    target: str
    prompt: str
    transformed_prompt: str | None = None
    response: str
    conversation_history: list[dict[str, Any]] = Field(default_factory=list)
    retrieval_trace: list[dict[str, Any]] = Field(default_factory=list)
    tool_trace: list[dict[str, Any]] = Field(default_factory=list)
    authorization_trace: list[dict[str, Any]] = Field(default_factory=list)
    evaluator_results: list[dict[str, Any]] = Field(default_factory=list)
    success: bool
    confidence: float
    timestamp: datetime = Field(default_factory=utc_now)
    latency_ms: int = 0
    token_usage: dict[str, int] = Field(default_factory=dict)
    cost_estimate: float = 0.0
    evidence_hash: str


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("FIND"))
    title: str
    description: str
    root_cause: str
    category: str
    affected_component: str
    severity: Severity
    likelihood: float
    technical_impact: float
    business_impact: float
    confidence: float
    reproducibility: float
    status: FindingStatus
    evidence_references: list[str]
    related_executions: list[str]
    duplicate_group: str | None = None
    remediation: str
    residual_risk: str
    owner: str
    retest_state: str = "not_started"


class ISOMapping(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ISO"))
    finding_id: str
    standard_version: str
    clause_or_control_id: str
    requirement_title: str
    mapping_rationale: str
    relevance_type: str
    required_organizational_evidence: list[str]
    available_evidence: list[str]
    missing_evidence: list[str]
    evidence_sufficiency: str
    mapping_confidence: float
    human_review_status: str = "required"
    reviewer_comment: str | None = None
    approval_status: str = "not_approved"


class AssessmentResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ASM"))
    scope: AssessmentScope
    target_mode: str
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    executions: list[AttackExecution] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    iso_mappings: list[ISOMapping] = Field(default_factory=list)
    reports: dict[str, str] = Field(default_factory=dict)
# ruff: noqa: E402, UP017
