from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .models import EnvironmentType, new_id, utc_now


class TargetType(str, Enum):
    enterprise_assist = "enterprise_assist"
    openai_compatible = "openai_compatible"
    ollama = "ollama"
    vllm = "vllm"
    custom_rest = "custom_rest"
    generic_rag = "generic_rag"
    generic_agent = "generic_agent"


class TargetVisibility(str, Enum):
    black_box = "black_box"
    grey_box = "grey_box"
    white_box = "white_box"


class AuthenticationType(str, Enum):
    none = "none"
    bearer = "bearer"
    api_key_header = "api_key_header"
    basic = "basic"
    custom_static_header = "custom_static_header"
    local_trusted = "local_trusted"


class DeploymentType(str, Enum):
    local = "local"
    remote_api = "remote_api"
    remote_lab = "remote_lab"
    staging = "staging"
    production = "production"


class TargetCredential(BaseModel):
    authentication_type: AuthenticationType = AuthenticationType.none
    header_name: str | None = None
    username: str | None = None
    secret_encrypted: str | None = None
    secret_preview: str | None = None
    last_updated_at: datetime = Field(default_factory=utc_now)


class TargetCapabilities(BaseModel):
    chat: bool = True
    multi_turn: bool = False
    streaming: bool = False
    system_prompt_configurable: bool = False
    system_prompt_observable: bool = False
    model_metadata: bool = False
    rag: bool = False
    retrieval_telemetry: bool = False
    document_metadata: bool = False
    tools: bool = False
    tool_telemetry: bool = False
    agent_actions: bool = False
    memory: bool = False
    memory_telemetry: bool = False
    user_roles: bool = False
    authentication: bool = False
    authorization_telemetry: bool = False
    confirmation_workflow: bool = False
    security_events: bool = False
    custom_headers: bool = False
    local_model: bool = False
    remote_model: bool = False
    openai_compatible: bool = False
    rate_limit_metadata: bool = False
    token_usage: bool = False
    request_ids: bool = False
    reset_session: bool = False
    deterministic_test_canaries: bool = False
    white_box: bool = False
    grey_box: bool = False
    black_box: bool = True

    def enabled(self) -> list[str]:
        return [name for name, value in self.model_dump().items() if value is True]


class TargetConfiguration(BaseModel):
    base_url: str | None = None
    health_path: str | None = "/health"
    chat_path: str | None = "/chat"
    models_path: str | None = "/v1/models"
    model_name: str | None = None
    request_timeout_seconds: float = 30.0
    max_retries: int = 1
    tls_verify: bool = True
    custom_headers: dict[str, str] = Field(default_factory=dict)
    default_system_message: str | None = None
    temperature: float = 0.0
    max_output_tokens: int = 512
    streaming: bool = False
    http_method: str = "POST"
    request_json_template: dict[str, Any] = Field(default_factory=dict)
    prompt_field_path: str = "message"
    session_field_path: str | None = "session_id"
    user_role_field_path: str | None = "user_role"
    response_text_path: str = "response"
    request_id_path: str | None = "request_id"
    telemetry_path: str | None = "telemetry"
    telemetry_endpoint: str | None = None
    retrieval_trace_endpoint: str | None = None
    tool_trace_endpoint: str | None = None
    context_size: int | None = None
    keep_alive: str | None = None
    organization_header: str | None = None
    project_header: str | None = None


class TargetRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("TGT"))
    organization: str
    system_name: str
    target_name: str
    target_type: TargetType
    environment: EnvironmentType = EnvironmentType.local_lab
    business_purpose: str = ""
    system_owner: str
    technical_owner: str = ""
    target_version: str = "unknown"
    model_provider: str = "unknown"
    model_name: str = "unknown"
    deployment_type: DeploymentType = DeploymentType.local
    criticality: str = "medium"
    data_classification: str = "synthetic"
    configuration: TargetConfiguration
    credential: TargetCredential = Field(default_factory=TargetCredential)
    declared_capabilities: TargetCapabilities = Field(default_factory=TargetCapabilities)
    discovered_capabilities: TargetCapabilities | None = None
    visibility: TargetVisibility = TargetVisibility.black_box
    enabled: bool = False
    disabled_reason: str | None = None
    authorization_confirmed: bool = False
    approved_testing_start: datetime | None = None
    approved_testing_end: datetime | None = None
    max_requests: int = 20
    max_duration_seconds: int = 1800
    max_concurrency: int = 1
    allowed_testing_categories: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(
        default_factory=lambda: [
            "denial of service",
            "credential attacks",
            "malware delivery",
            "persistence",
            "destructive tool execution",
        ]
    )
    emergency_contact: str = ""
    kill_switch_acknowledged: bool = False
    last_health: TargetHealth | None = None
    last_validated_at: datetime | None = None
    last_assessment_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ConfigurationValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    decisions: list[str] = Field(default_factory=list)


class TargetHealth(BaseModel):
    status: str
    reachable: bool
    status_code: int | None = None
    latency_ms: int | None = None
    message: str = ""
    checked_at: datetime = Field(default_factory=utc_now)


class AuthenticationTestResult(BaseModel):
    status: str
    authenticated: bool
    message: str = ""


class SessionContext(BaseModel):
    user_id: str = "authorized-assessor"
    user_role: str = "standard_employee"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetSession(BaseModel):
    session_id: str = Field(default_factory=lambda: new_id("SES"))
    context: SessionContext
    created_at: datetime = Field(default_factory=utc_now)


class TargetMessageRequest(BaseModel):
    prompt: str
    session_id: str | None = None
    user_id: str = "authorized-assessor"
    user_role: str = "standard_employee"
    system_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetTelemetry(BaseModel):
    visibility: TargetVisibility = TargetVisibility.black_box
    retrieval_trace: list[dict[str, Any]] = Field(default_factory=list)
    tool_trace: list[dict[str, Any]] = Field(default_factory=list)
    authorization_trace: list[dict[str, Any]] = Field(default_factory=list)
    memory_trace: list[dict[str, Any]] = Field(default_factory=list)
    security_events: list[dict[str, Any]] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)


class TargetMessageResponse(BaseModel):
    request_id: str = Field(default_factory=lambda: new_id("REQ"))
    text: str
    raw_response: dict[str, Any] = Field(default_factory=dict)
    status_code: int | None = None
    latency_ms: int = 0
    token_usage: dict[str, int] = Field(default_factory=dict)
    telemetry: TargetTelemetry = Field(default_factory=TargetTelemetry)


class SanitizedTargetResponse(BaseModel):
    request_id: str
    text: str
    status_code: int | None = None
    latency_ms: int
    token_usage: dict[str, int] = Field(default_factory=dict)
    telemetry: TargetTelemetry


class SupportedCampaign(BaseModel):
    key: str
    category: str
    supported: bool
    evidence_basis: str
    missing_capabilities: list[str] = Field(default_factory=list)

