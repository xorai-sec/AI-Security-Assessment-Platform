from __future__ import annotations

import os
from typing import Any

from packages.target_sdk import TargetMessage, TargetSDKClient


class TargetProxyClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token or os.getenv("TARGET_PROXY_SECRET", "development-target-proxy-secret")
        self.timeout = timeout
        self.sdk = TargetSDKClient(self.base_url, token=self.token, timeout=self.timeout)

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
        payload = TargetMessage(
            execution_id=execution_id,
            campaign_id=campaign_id,
            prompt=prompt,
            session_id=session_id,
            user_role=user_role,
            metadata=metadata or {},
        )
        response = await self.sdk.send_message(target_id, payload)
        return response.raw
