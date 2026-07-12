from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

import httpx

from ...evidence import redact_text
from ...target_models import (
    AuthenticationTestResult,
    ConfigurationValidationResult,
    SanitizedTargetResponse,
    SessionContext,
    TargetCapabilities,
    TargetConfiguration,
    TargetCredential,
    TargetHealth,
    TargetMessageRequest,
    TargetMessageResponse,
    TargetSession,
    TargetTelemetry,
    TargetVisibility,
)
from ...target_security import DevelopmentCredentialProtector, NetworkPolicy, validate_target_url


class AITargetAdapter(ABC):
    def __init__(
        self,
        config: TargetConfiguration,
        credential: TargetCredential | None = None,
        network_policy: NetworkPolicy | None = None,
    ) -> None:
        self.config = config
        self.credential = credential or TargetCredential()
        self.network_policy = network_policy or NetworkPolicy.from_env()
        self.credential_protector = DevelopmentCredentialProtector()

    async def validate_configuration(self, config: TargetConfiguration | None = None) -> ConfigurationValidationResult:
        config = config or self.config
        if not config.base_url:
            return ConfigurationValidationResult(valid=False, errors=["base_url is required"])
        return validate_target_url(config.base_url, self.network_policy)

    @abstractmethod
    async def health_check(self) -> TargetHealth:
        ...

    @abstractmethod
    async def discover_capabilities(self) -> TargetCapabilities:
        ...

    @abstractmethod
    async def send_message(self, request: TargetMessageRequest) -> TargetMessageResponse:
        ...

    async def create_session(self, session_context: SessionContext) -> TargetSession:
        return TargetSession(context=session_context)

    async def close_session(self, session_id: str) -> None:
        return None

    async def reset_session(self, session_id: str) -> None:
        return None

    async def get_telemetry(self, request_id: str) -> TargetTelemetry:
        return TargetTelemetry(unavailable=["target did not expose telemetry lookup"])

    async def test_authentication(self) -> AuthenticationTestResult:
        health = await self.health_check()
        return AuthenticationTestResult(
            status="passed" if health.reachable else "failed",
            authenticated=health.reachable,
            message=health.message,
        )

    async def sanitize_for_storage(self, response: TargetMessageResponse) -> SanitizedTargetResponse:
        return SanitizedTargetResponse(
            request_id=response.request_id,
            text=redact_text(response.text),
            status_code=response.status_code,
            latency_ms=response.latency_ms,
            token_usage=response.token_usage,
            telemetry=response.telemetry,
        )

    def headers(self) -> dict[str, str]:
        headers = dict(self.config.custom_headers)
        secret = self.credential_protector.decrypt(self.credential.secret_encrypted)
        if self.credential.authentication_type == "bearer" and secret:
            headers["Authorization"] = f"Bearer {secret}"
        elif self.credential.authentication_type == "api_key_header" and self.credential.header_name and secret:
            headers[self.credential.header_name] = secret
        elif self.credential.authentication_type == "custom_static_header" and self.credential.header_name and secret:
            headers[self.credential.header_name] = secret
        return headers

    async def _get_json(self, url: str) -> tuple[dict[str, Any], int, int]:
        started = time.perf_counter()
        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            verify=self.config.tls_verify,
            follow_redirects=False,
        ) as client:
            response = await client.get(url, headers=self.headers())
            latency_ms = int((time.perf_counter() - started) * 1000)
            response.raise_for_status()
            return response.json(), response.status_code, latency_ms

    async def _post_json(self, url: str, payload: dict[str, Any]) -> tuple[dict[str, Any], int, int]:
        started = time.perf_counter()
        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            verify=self.config.tls_verify,
            follow_redirects=False,
        ) as client:
            response = await client.post(url, json=payload, headers=self.headers())
            latency_ms = int((time.perf_counter() - started) * 1000)
            response.raise_for_status()
            return response.json(), response.status_code, latency_ms


def field_get(data: dict[str, Any], path: str | None, default: Any = None) -> Any:
    if not path:
        return default
    current: Any = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return default
    return current


def field_set(data: dict[str, Any], path: str, value: Any) -> None:
    parts = [part for part in path.split(".") if part]
    if not parts:
        return
    current = data
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value


def black_box_response(text: str, status_code: int | None, latency_ms: int, raw: dict[str, Any]) -> TargetMessageResponse:
    return TargetMessageResponse(
        text=text,
        raw_response=raw,
        status_code=status_code,
        latency_ms=latency_ms,
        telemetry=TargetTelemetry(visibility=TargetVisibility.black_box, unavailable=["retrieval", "tools", "memory"]),
    )
