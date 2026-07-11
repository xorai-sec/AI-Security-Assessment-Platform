from __future__ import annotations

import os
from typing import Any

import httpx

from workers.common.protocol.schemas import TargetProxyMessageRequest


class TargetProxyClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token or os.getenv("TARGET_PROXY_SECRET", "development-target-proxy-secret")
        self.timeout = timeout

    async def send_message(
        self,
        target_id: str,
        execution_id: str,
        campaign_id: str,
        prompt: str,
        session_id: str | None = None,
        user_role: str = "standard_employee",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = TargetProxyMessageRequest(
            execution_id=execution_id,
            campaign_id=campaign_id,
            prompt=prompt,
            session_id=session_id,
            user_role=user_role,
            metadata=metadata or {},
        ).model_dump(mode="json")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/internal/targets/{target_id}/message",
                json=payload,
                headers={"X-Target-Proxy-Token": self.token},
            )
            response.raise_for_status()
            return response.json()

