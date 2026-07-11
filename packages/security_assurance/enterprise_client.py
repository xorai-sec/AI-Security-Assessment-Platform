from __future__ import annotations

import time
from typing import Any

import httpx


class EnterpriseAssistClient:
    def __init__(self, base_url: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def chat(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        started = time.perf_counter()
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(f"{self.base_url}/chat", json=payload)
            response.raise_for_status()
            data = response.json()
        latency_ms = int((time.perf_counter() - started) * 1000)
        return data, latency_ms

    def health(self) -> dict[str, Any]:
        with httpx.Client(timeout=10) as client:
            response = client.get(f"{self.base_url}/health")
            response.raise_for_status()
            return response.json()

