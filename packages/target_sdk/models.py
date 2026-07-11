from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TargetMessage(BaseModel):
    execution_id: str
    campaign_id: str
    prompt: str
    session_id: str | None = None
    user_role: str = "standard_employee"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    text: str = ""
    latency_ms: int = 0
    telemetry: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
