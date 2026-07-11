from __future__ import annotations

from datetime import datetime
from typing import Any

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
    objective: str = "Authorized AI security assessment"
    category: str = "multi_framework"
    strategy: str = "baseline"
    maximum_requests: int = 20
    maximum_duration_seconds: int = 900
    written_authorization_confirmed: bool = True


class FrameworkAssessmentResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("MFASM"))
    target_id: str
    frameworks: list[str]
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    status: str = "running"
    worker_results: list[dict[str, Any]] = Field(default_factory=list)
    normalized_evidence: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    reports: dict[str, str] = Field(default_factory=dict)

