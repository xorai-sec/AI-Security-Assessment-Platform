"""Provider-neutral, auditable model-role gateway.

The gateway deliberately contains no framework-specific attack behavior. It
only resolves role configuration, performs bounded provider calls, and emits
redacted invocation metadata suitable for evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

UTC = timezone.utc  # noqa: UP017

RoleName = Literal["attacker", "judge", "planner", "embedding", "target"]


class ModelManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str
    source_revision: str | None = None
    sha256: str | None = None
    quantization: str | None = None
    license: str | None = None


class ModelRoleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: RoleName
    model: str
    base_url: str
    provider: Literal["ollama", "openai_compatible"] = "openai_compatible"
    timeout_seconds: float = Field(default=60, gt=0, le=300)
    max_retries: int = Field(default=1, ge=0, le=3)
    max_input_chars: int = Field(default=32_000, gt=0)
    max_output_chars: int = Field(default=16_000, gt=0)
    manifest: ModelManifest | None = None

    @field_validator("base_url")
    @classmethod
    def no_credentials_in_url(cls, value: str) -> str:
        parsed = httpx.URL(value)
        if parsed.username or parsed.password:
            raise ValueError("model endpoint must not contain credentials")
        return value.rstrip("/")


class InvocationEvidence(BaseModel):
    invocation_id: str
    role: RoleName
    model: str
    endpoint_type: str
    started_at: datetime
    completed_at: datetime
    latency_ms: int
    request_hash: str
    response_hash: str | None = None
    token_usage: dict[str, int] = Field(default_factory=dict)
    success: bool
    error: str | None = None


class ModelGatewayError(RuntimeError):
    pass


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def redact_secrets(value: Any) -> Any:
    """Return JSON-safe data with credentials and authorization headers removed."""
    if isinstance(value, dict):
        hidden = {"authorization", "proxy-authorization", "api_key", "token", "secret"}
        return {k: "[REDACTED]" if k.lower() in hidden else redact_secrets(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


class ModelRoleGateway:
    def __init__(self, roles: dict[RoleName, ModelRoleConfig], *, distinct: bool = True, allow_same: bool = False) -> None:
        self.roles = roles
        self.distinct = distinct
        self.allow_same = allow_same

    @classmethod
    def from_environment(cls) -> ModelRoleGateway:
        def role(name: RoleName, default_provider: str = "openai_compatible") -> ModelRoleConfig | None:
            upper = name.upper()
            model = os.getenv(f"{upper}_MODEL") or os.getenv(f"OLLAMA_{upper}_MODEL")
            base = os.getenv(f"{upper}_BASE_URL") or os.getenv("OLLAMA_BASE_URL")
            if not model or not base:
                return None
            provider = "ollama" if "11434" in base or default_provider == "ollama" else "openai_compatible"
            return ModelRoleConfig(role=name, model=model, base_url=base, provider=provider)  # type: ignore[arg-type]

        roles = {name: config for name in ("attacker", "judge", "planner", "embedding", "target") if (config := role(name))}
        return cls(
            roles,  # type: ignore[arg-type]
            distinct=os.getenv("REQUIRE_DISTINCT_MODEL_ROLES", "true").lower() == "true",
            allow_same=os.getenv("ALLOW_SAME_MODEL_EVAL", "false").lower() == "true",
        )

    def validate_required(self, required: tuple[RoleName, ...] = ("attacker", "judge")) -> None:
        missing = [role for role in required if role not in self.roles]
        if missing:
            raise ModelGatewayError(f"Required model roles unavailable: {', '.join(missing)}")
        if self.distinct and not self.allow_same:
            models = [self.roles[role].model for role in required]
            if len(set(models)) != len(models):
                raise ModelGatewayError("Required model roles must use distinct models")

    def _request(self, config: ModelRoleConfig, prompt: str, *, json_response: bool = False) -> tuple[Any, InvocationEvidence]:
        if len(prompt) > config.max_input_chars:
            raise ModelGatewayError(f"input exceeds {config.max_input_chars} characters")
        invocation_id = f"model-{uuid.uuid4().hex}"
        started = datetime.now(UTC)
        request_payload: dict[str, Any]
        if config.provider == "ollama":
            url = f"{config.base_url}/api/generate"
            request_payload = {"model": config.model, "prompt": prompt, "stream": False, "format": "json" if json_response else None}
            request_payload = {key: value for key, value in request_payload.items() if value is not None}
        else:
            url = f"{config.base_url}/chat/completions" if not config.base_url.endswith("/v1") else f"{config.base_url}/chat/completions"
            request_payload = {"model": config.model, "messages": [{"role": "user", "content": prompt}], "temperature": 0}
            if json_response:
                request_payload["response_format"] = {"type": "json_object"}
        request_hash = _sha(request_payload)
        error: str | None = None
        response_data: Any = None
        for attempt in range(config.max_retries + 1):
            try:
                response = httpx.post(url, json=request_payload, timeout=config.timeout_seconds)
                response.raise_for_status()
                response_data = response.json()
                text = response_data.get("response") if config.provider == "ollama" else response_data["choices"][0]["message"]["content"]
                if not isinstance(text, str) or len(text) > config.max_output_chars:
                    raise ModelGatewayError("model response is oversized or malformed")
                if json_response:
                    text = json.loads(text)
                usage = response_data.get("usage", {}) if isinstance(response_data, dict) else {}
                if config.provider == "ollama":
                    usage = {"prompt_tokens": response_data.get("prompt_eval_count", 0), "completion_tokens": response_data.get("eval_count", 0)}
                completed = datetime.now(UTC)
                return text, InvocationEvidence(invocation_id=invocation_id, role=config.role, model=config.model, endpoint_type=config.provider, started_at=started, completed_at=completed, latency_ms=int((completed-started).total_seconds()*1000), request_hash=request_hash, response_hash=_sha(text), token_usage={k: int(v) for k, v in usage.items() if isinstance(v, int)}, success=True)
            except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError, ModelGatewayError) as exc:
                error = str(exc)
                if attempt >= config.max_retries:
                    break
        completed = datetime.now(UTC)
        raise ModelGatewayError(f"{config.role} invocation failed: {error}")

    def invoke(self, role: RoleName, prompt: str, *, json_response: bool = False) -> tuple[Any, InvocationEvidence]:
        config = self.roles.get(role)
        if not config:
            raise ModelGatewayError(f"model role unavailable: {role}")
        return self._request(config, prompt, json_response=json_response)

    def health(self, role: RoleName) -> dict[str, Any]:
        config = self.roles.get(role)
        if not config:
            return {"role": role, "healthy": False, "error": "role unavailable"}
        try:
            path = "/api/tags" if config.provider == "ollama" else "/models"
            response = httpx.get(f"{config.base_url}{path}", timeout=config.timeout_seconds)
            response.raise_for_status()
            return {"role": role, "healthy": True, "model": config.model, "endpoint_type": config.provider}
        except Exception as exc:
            return {"role": role, "healthy": False, "error": str(exc)}
