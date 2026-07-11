from __future__ import annotations

from copy import deepcopy

from ...target_models import TargetCapabilities, TargetHealth, TargetMessageRequest, TargetMessageResponse, TargetTelemetry, TargetVisibility
from ...target_security import join_url
from .base import AITargetAdapter, field_get, field_set


class CustomRESTTargetAdapter(AITargetAdapter):
    async def validate_configuration(self, config=None):
        result = await super().validate_configuration(config)
        config = config or self.config
        if not config.response_text_path:
            result.errors.append("response_text_path is required for custom REST targets.")
        if config.http_method.upper() != "POST":
            result.errors.append("Only POST custom REST chat mappings are currently supported.")
        result.valid = not result.errors
        return result

    async def health_check(self) -> TargetHealth:
        try:
            path = self.config.health_path or ""
            data, status_code, latency_ms = await self._get_json(join_url(self.config.base_url or "", path))
            return TargetHealth(status="healthy", reachable=True, status_code=status_code, latency_ms=latency_ms, message=str(data)[:500])
        except Exception as exc:
            return TargetHealth(status="degraded", reachable=False, message=f"Health endpoint failed: {exc}")

    async def discover_capabilities(self) -> TargetCapabilities:
        return TargetCapabilities(
            chat=True,
            multi_turn=bool(self.config.session_field_path),
            rag=bool(self.config.retrieval_trace_endpoint),
            retrieval_telemetry=bool(self.config.retrieval_trace_endpoint),
            tools=bool(self.config.tool_trace_endpoint),
            tool_telemetry=bool(self.config.tool_trace_endpoint),
            custom_headers=bool(self.config.custom_headers),
            authentication=self.credential.authentication_type != "none",
            request_ids=bool(self.config.request_id_path),
            black_box=not bool(self.config.telemetry_path),
            grey_box=bool(self.config.telemetry_path),
        )

    async def send_message(self, request: TargetMessageRequest) -> TargetMessageResponse:
        payload = deepcopy(self.config.request_json_template or {})
        field_set(payload, self.config.prompt_field_path, request.prompt)
        if self.config.session_field_path and request.session_id:
            field_set(payload, self.config.session_field_path, request.session_id)
        if self.config.user_role_field_path:
            field_set(payload, self.config.user_role_field_path, request.user_role)
        raw, status_code, latency_ms = await self._post_json(join_url(self.config.base_url or "", self.config.chat_path), payload)
        telemetry = field_get(raw, self.config.telemetry_path, {}) or {}
        return TargetMessageResponse(
            request_id=str(field_get(raw, self.config.request_id_path, "")),
            text=str(field_get(raw, self.config.response_text_path, "")),
            raw_response=raw,
            status_code=status_code,
            latency_ms=latency_ms,
            telemetry=TargetTelemetry(
                visibility=TargetVisibility.grey_box if telemetry else TargetVisibility.black_box,
                retrieval_trace=telemetry.get("retrieval_trace", []),
                tool_trace=telemetry.get("tool_trace", []),
                authorization_trace=telemetry.get("authorization_trace", []),
                unavailable=[] if telemetry else ["retrieval", "tools", "memory", "authorization"],
            ),
        )

