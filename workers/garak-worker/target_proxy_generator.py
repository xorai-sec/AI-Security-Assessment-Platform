from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Union

import requests

from garak import _config
from garak.attempt import Conversation, Message
from garak.exception import BadGeneratorException
from garak.generators.base import Generator


class TargetProxyGenerator(Generator):
    """AI Security Platform target-proxy generator for authorized garak scans."""

    generator_family_name = "AISEC_TARGET_PROXY"
    ENV_VAR = None
    parallel_capable = False
    supports_multiple_generations = False
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "api_base_url": "http://api:8080",
        "target_id": None,
        "execution_id": None,
        "campaign_id": "CMP-garak",
        "target_proxy_secret": "development-target-proxy-secret",
        "user_role": "standard_employee",
        "request_timeout": 60,
        "traffic_path": None,
    }
    _supported_params = (
        "api_base_url",
        "target_id",
        "execution_id",
        "campaign_id",
        "target_proxy_secret",
        "user_role",
        "request_timeout",
        "traffic_path",
        "name",
        "max_tokens",
        "temperature",
        "top_k",
        "context_len",
        "skip_seq_start",
        "skip_seq_end",
    )

    def __init__(self, name: str = "", config_root=_config):
        super().__init__(name=name or "target-proxy", config_root=config_root)
        if not self.target_id:
            raise BadGeneratorException("TargetProxyGenerator requires target_id")
        if not self.execution_id:
            raise BadGeneratorException("TargetProxyGenerator requires execution_id")
        self.target_proxy_secret = self.target_proxy_secret or os.getenv(
            "TARGET_PROXY_SECRET", "development-target-proxy-secret"
        )
        self.api_base_url = self.api_base_url.rstrip("/")
        if self.traffic_path:
            Path(self.traffic_path).parent.mkdir(parents=True, exist_ok=True)

    def _write_traffic(self, payload: dict, response_payload: dict | None, error: str | None = None) -> None:
        if not self.traffic_path:
            return
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "generator": "garak.generators.target_proxy.TargetProxyGenerator",
            "payload": payload,
            "response": response_payload,
            "error": error,
        }
        with Path(self.traffic_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        prompt_text = prompt.last_message().text
        payload = {
            "execution_id": self.execution_id,
            "campaign_id": self.campaign_id,
            "prompt": prompt_text,
            "session_id": f"{self.execution_id}-garak-native",
            "user_role": self.user_role,
            "metadata": {
                "framework": "garak",
                "source": "garak-native-generator",
                "generator": "garak.generators.target_proxy.TargetProxyGenerator",
            },
        }
        try:
            response = requests.post(
                f"{self.api_base_url}/internal/targets/{self.target_id}/message",
                json=payload,
                headers={"X-Target-Proxy-Token": self.target_proxy_secret},
                timeout=self.request_timeout,
            )
            response.raise_for_status()
            data = response.json()
            self._write_traffic(payload, data)
            return [Message(str(data.get("text", "")))]
        except Exception as exc:
            self._write_traffic(payload, None, str(exc))
            raise BadGeneratorException(f"Target proxy request failed: {exc}") from exc


DEFAULT_CLASS = "TargetProxyGenerator"
