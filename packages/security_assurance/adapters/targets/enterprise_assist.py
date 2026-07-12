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


class EnterpriseAssistTargetAdapter(AITargetAdapter):
    async def health_check(self) -> TargetHealth:
        try:
            data, status_code, latency_ms = await self._get_json(join_url(self.config.base_url or "", self.config.health_path))
            return TargetHealth(status="healthy", reachable=True, status_code=status_code, latency_ms=latency_ms, message=str(data))
        except Exception as exc:
            return TargetHealth(status="unhealthy", reachable=False, message=str(exc))

    async def discover_capabilities(self) -> TargetCapabilities:
        return TargetCapabilities(
            chat=True,
            multi_turn=True,
            rag=True,
            retrieval_telemetry=True,
            document_metadata=True,
            tools=True,
            tool_telemetry=True,
            memory=True,
            memory_telemetry=True,
            user_roles=True,
            authorization_telemetry=True,
            confirmation_workflow=True,
            request_ids=True,
            reset_session=True,
            deterministic_test_canaries=True,
            white_box=True,
            grey_box=True,
            black_box=False,
        )

    async def send_message(self, request: TargetMessageRequest) -> TargetMessageResponse:
        payload = {
            "message": request.prompt,
            "user_role": request.user_role,
            "user_id": request.user_id,
            "session_id": request.session_id,
            "mode": request.metadata.get("mode", "vulnerable"),
            "confirm_external_action": request.metadata.get("confirm_external_action", False),
        }
        raw, status_code, latency_ms = await self._post_json(join_url(self.config.base_url or "", self.config.chat_path), payload)
        telemetry = raw.get("telemetry", {})
        return TargetMessageResponse(
            text=str(raw.get("response", "")),
            raw_response=raw,
            status_code=status_code,
            latency_ms=latency_ms,
            telemetry=TargetTelemetry(
                visibility=TargetVisibility.white_box,
                retrieval_trace=telemetry.get("retrieval_trace", []),
                tool_trace=telemetry.get("tool_trace", []),
                authorization_trace=telemetry.get("authorization_trace", []),
                memory_trace=telemetry.get("memory_trace", []),
            ),
            token_usage=field_get(raw, "usage", {}),
        )

