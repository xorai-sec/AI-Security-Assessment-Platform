from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from .models import new_id, utc_now


class FrameworkDefinition(BaseModel):
    id: str
    name: str
    worker_url: str
    enabled: bool = False
    capabilities: list[str] = Field(default_factory=list)
    version: str | None = None
    health: str = "unknown"
    last_health_check: datetime | None = None
    last_error: str | None = None


class FrameworkAssessmentRequest(BaseModel):
    target_id: str
    frameworks: list[str] = Field(default_factory=lambda: ["native"])
    execution_mode: Literal["parallel", "chained"] = "parallel"
    objective: str = "Authorized AI security assessment"
    category: str = "multi_framework"
    strategy: str = "baseline"
    profile: Literal["quick", "standard", "comprehensive", "deep-owasp", "deep-owasp-4h", "deep-owasp-large"] = "quick"
    target_model: str | None = None
    attacker_model: str | None = None
    judge_model: str | None = None
    allow_same_model_eval: bool = False
    maximum_requests: int = 20
    maximum_duration_seconds: int = 900
    maximum_turns: int = 5
    maximum_concurrency: int = 1
    maximum_tokens: int = 2048
    probe_families: list[str] = Field(default_factory=list)
    promptfoo_plugins: list[str] = Field(default_factory=list)
    promptfoo_strategies: list[str] = Field(default_factory=list)
    adaptive_minimum_frameworks: int = 3
    continue_on_framework_error: bool = True
    written_authorization_confirmed: bool = True
    # PyRIT 0.13.0 exposes PromptSendingAttack as the supported public
    # attack class.  Do not advertise techniques whose classes are absent.
    pyrit_attack: Literal["prompt_sending"] | None = None
    pyrit_max_attacker_calls: int = Field(default=4, ge=1, le=8)


class FrameworkAssessmentResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("MFASM"))
    target_id: str
    frameworks: list[str]
    strategy: str = "baseline"
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    status: str = "running"
    worker_results: list[dict[str, Any]] = Field(default_factory=list)
    normalized_evidence: list[dict[str, Any]] = Field(default_factory=list)
    execution_plan: list[dict[str, Any]] = Field(default_factory=list)
    chain_events: list[dict[str, Any]] = Field(default_factory=list)
    evidence_signals: list[dict[str, Any]] = Field(default_factory=list)
    attack_opportunities: list[dict[str, Any]] = Field(default_factory=list)
    handoff_plans: list[dict[str, Any]] = Field(default_factory=list)
    adaptive_artifacts: dict[str, str] = Field(default_factory=dict)
    correlated_findings: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    reports: dict[str, str] = Field(default_factory=dict)
