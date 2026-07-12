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
from .base import AITargetAdapter


class OllamaTargetAdapter(AITargetAdapter):
    async def health_check(self) -> TargetHealth:
        try:
            data, status_code, latency_ms = await self._get_json(join_url(self.config.base_url or "", "/api/tags"))
            models = [model.get("name") for model in data.get("models", [])]
            if self.config.model_name and self.config.model_name not in models:
                return TargetHealth(status="degraded", reachable=True, status_code=status_code, latency_ms=latency_ms, message=f"Model not installed: {self.config.model_name}")
            return TargetHealth(status="healthy", reachable=True, status_code=status_code, latency_ms=latency_ms, message=f"Models: {models}")
        except Exception as exc:
            return TargetHealth(status="unhealthy", reachable=False, message=str(exc))

    async def discover_capabilities(self) -> TargetCapabilities:
        return TargetCapabilities(
            chat=True,
            multi_turn=True,
            streaming=self.config.streaming,
            model_metadata=True,
            local_model=True,
            token_usage=False,
            black_box=True,
        )

    async def send_message(self, request: TargetMessageRequest) -> TargetMessageResponse:
        payload = {
            "model": self.config.model_name,
            "messages": [{"role": "user", "content": request.prompt}],
            "stream": False,
            "keep_alive": self.config.keep_alive,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_output_tokens,
            },
        }
        raw, status_code, latency_ms = await self._post_json(join_url(self.config.base_url or "", "/api/chat"), payload)
        message = raw.get("message", {})
        return TargetMessageResponse(
            text=str(message.get("content", "")),
            raw_response=raw,
            status_code=status_code,
            latency_ms=latency_ms,
            telemetry=TargetTelemetry(visibility=TargetVisibility.black_box, unavailable=["retrieval", "tools", "memory", "authorization"]),
        )

