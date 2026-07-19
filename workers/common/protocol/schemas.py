from __future__ import annotations

from datetime import datetime, timezone

UTC = timezone.utc
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


ExecutionState = Literal["queued", "starting", "running", "cancelling", "cancelled", "succeeded", "failed", "timed_out", "partially_completed"]


class FrameworkTarget(BaseModel):
    target_id: str
    target_type: str
    internal_proxy_url: str
    visibility: str = "black_box"
    model_name: str = "unknown"


AssessmentProfile = Literal["quick", "standard", "comprehensive", "deep-owasp", "deep-owasp-4h", "deep-owasp-large"]


class ModelRoles(BaseModel):
    target_model: str = "unknown"
    attacker_model: str | None = None
    judge_model: str | None = None
    allow_same_model_eval: bool = False
    bias_warning: str | None = None


class ExecutionLimits(BaseModel):
    maximum_requests: int = 20
    maximum_duration_seconds: int = 900
    maximum_turns: int = 5
    maximum_concurrency: int = 1
    maximum_tokens: int = 2048


class FrameworkExecutionRequest(BaseModel):
    execution_id: str = Field(default_factory=lambda: new_id("FWEXEC"))
    assessment_id: str
    campaign_id: str
    target: FrameworkTarget
    objective: str
    category: str
    strategy: str = "baseline"
    profile: AssessmentProfile = "quick"
    model_roles: ModelRoles = Field(default_factory=ModelRoles)
    limits: ExecutionLimits = Field(default_factory=ExecutionLimits)
    configuration: dict[str, Any] = Field(default_factory=dict)
    callback_url: str | None = None


class WorkerCapability(BaseModel):
    name: str
    supported: bool
    detail: str = ""


class WorkerHealth(BaseModel):
    framework: str
    status: str
    version: str | None = None
    message: str = ""
    checked_at: datetime = Field(default_factory=utc_now)


class TargetProxyMessageRequest(BaseModel):
    execution_id: str
    campaign_id: str
    prompt: str
    session_id: str | None = None
    user_role: str = "standard_employee"
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedFrameworkEvidence(BaseModel):
    execution_id: str
    assessment_id: str
    campaign_id: str
    framework: str
    framework_version: str | None = None
    worker_version: str = "0.1.0"
    target_id: str
    target_type: str
    target_version: str = "unknown"
    model_name: str = "unknown"
    attacker_model: str | None = None
    judge_model: str | None = None
    profile: AssessmentProfile = "quick"
    visibility: str = "black_box"
    category: str
    objective: str
    strategy: str
    probe: str | None = None
    detector: str | None = None
    converter: str | None = None
    vulnerability: str | None = None
    attack_method: str | None = None
    prompt: str
    response: str
    conversation_trace: list[dict[str, Any]] = Field(default_factory=list)
    retrieval_trace: list[dict[str, Any]] | None = None
    tool_trace: list[dict[str, Any]] | None = None
    authorization_trace: list[dict[str, Any]] | None = None
    memory_trace: list[dict[str, Any]] | None = None
    evaluator_results: list[dict[str, Any]] = Field(default_factory=list)
    raw_score: float = 0.0
    success: bool = False
    candidate: bool = True
    confirmed: bool = False
    confidence: float = 0.0
    native_engine_invoked: bool = False
    native_command_or_api: str | None = None
    native_framework_version: str | None = None
    native_artifact_path: str | None = None
    native_plugin_identifiers: list[str] = Field(default_factory=list)
    fallback_used: bool = False
    fallback_reason: str | None = None
    evidence_limitations: list[str] = Field(default_factory=list)
    bias_warning: str | None = None
    request_count: int = 1
    latency_ms: int = 0
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)
    stop_reason: str = "completed"
    raw_artifact_reference: str | None = None
    evidence_hash: str
    opportunity_id: str | None = None
    source_evidence_ids: list[str] = Field(default_factory=list)
    handoff_rationale: str | None = None
    owasp_llm_mapping: list[str] = Field(default_factory=list)
    iso_42001_evidence_relevance: list[str] = Field(default_factory=list)
    expected_safe_behavior: str | None = None
    attack_category: str | None = None
    weakness_type: str | None = None
    assessment_canary: str | None = None


class FrameworkExecutionResult(BaseModel):
    execution_id: str
    framework: str
    status: ExecutionState
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    raw_artifacts: list[str] = Field(default_factory=list)
    evidence: list[NormalizedFrameworkEvidence] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    native_engine_invoked: bool = False
    native_command_or_api: str | None = None
    native_framework_version: str | None = None
    native_artifact_path: str | None = None
    native_plugin_identifiers: list[str] = Field(default_factory=list)
    fallback_used: bool = False
    fallback_reason: str | None = None
# ruff: noqa: E402, UP017
