from __future__ import annotations

from ...target_models import (
    TargetCapabilities,
    TargetHealth,
    TargetMessageRequest,
    TargetMessageResponse,
    TargetTelemetry,
    TargetVisibility,
)
from ...target_security import join_url
from .base import AITargetAdapter, field_get


class OpenAICompatibleTargetAdapter(AITargetAdapter):
    async def health_check(self) -> TargetHealth:
        if self.config.models_path:
            try:
                data, status_code, latency_ms = await self._get_json(join_url(self.config.base_url or "", self.config.models_path))
                return TargetHealth(status="healthy", reachable=True, status_code=status_code, latency_ms=latency_ms, message=str(data)[:500])
            except Exception as exc:
                return TargetHealth(status="degraded", reachable=False, message=f"model list unavailable: {exc}")
        return TargetHealth(status="unknown", reachable=True, message="No health or model endpoint configured")

    async def discover_capabilities(self) -> TargetCapabilities:
        caps = TargetCapabilities(
            chat=True,
            multi_turn=True,
            streaming=self.config.streaming,
            system_prompt_configurable=bool(self.config.default_system_message),
            model_metadata=True,
            authentication=self.credential.authentication_type != "none",
            custom_headers=bool(self.config.custom_headers),
            remote_model=True,
            openai_compatible=True,
            token_usage=True,
            request_ids=True,
            black_box=True,
        )
        return caps

    async def send_message(self, request: TargetMessageRequest) -> TargetMessageResponse:
        messages = []
        system_message = request.system_message or self.config.default_system_message
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": request.prompt})
        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_output_tokens,
            "stream": False,
        }
        raw, status_code, latency_ms = await self._post_json(join_url(self.config.base_url or "", self.config.chat_path or "/v1/chat/completions"), payload)
        text = field_get(raw, "choices.0.message.content")
        if text is None:
            choices = raw.get("choices", [])
            if choices and isinstance(choices[0], dict):
                text = field_get(choices[0], "message.content", field_get(choices[0], "text", ""))
        return TargetMessageResponse(
            request_id=str(raw.get("id") or ""),
            text=str(text or ""),
            raw_response=raw,
            status_code=status_code,
            latency_ms=latency_ms,
            token_usage=raw.get("usage", {}),
            telemetry=TargetTelemetry(visibility=TargetVisibility.black_box, unavailable=["retrieval", "tools", "memory", "authorization"]),
        )


class VLLMTargetAdapter(OpenAICompatibleTargetAdapter):
    async def discover_capabilities(self) -> TargetCapabilities:
        caps = await super().discover_capabilities()
        caps.local_model = True
        caps.remote_model = False
        caps.openai_compatible = True
        return caps

