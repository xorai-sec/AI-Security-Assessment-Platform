from __future__ import annotations

import os
from typing import Any

import httpx

from .errors import TargetSDKError
from .models import TargetMessage, TargetResponse


class TargetSDKClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token or os.getenv("TARGET_PROXY_SECRET", "development-target-proxy-secret")
        self.timeout = timeout

    async def send_message(self, target_id: str, message: TargetMessage) -> TargetResponse:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/internal/targets/{target_id}/message",
                    json=message.model_dump(mode="json"),
                    headers={"X-Target-Proxy-Token": self.token},
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except Exception as exc:
            raise TargetSDKError(f"target proxy request failed for {target_id}: {exc}") from exc
        return TargetResponse(
            text=str(data.get("text", "")),
            latency_ms=int(data.get("latency_ms", 0) or 0),
            telemetry=data.get("telemetry", {}) or {},
            raw=data,
        )
