import os

import httpx


API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")
BASE_URL = os.getenv("AISEC_OPENAI_FIXTURE_URL", "http://enterprise-assist:8090")


def main() -> None:
    payload = {
        "organization": "Contoso Global",
        "system_name": "OpenAI Compatible Fixture",
        "target_name": "OpenAI-compatible local fixture",
        "target_type": "openai_compatible",
        "system_owner": "AI Platform Owner",
        "technical_owner": "AI Engineering",
        "model_provider": "local-fixture",
        "model_name": "enterprise-assist-openai-fixture",
        "authorization_confirmed": True,
        "kill_switch_acknowledged": True,
        "configuration": {
            "base_url": BASE_URL,
            "health_path": "/health",
            "chat_path": "/v1/chat/completions",
            "models_path": "/v1/models",
            "model_name": "enterprise-assist-openai-fixture",
        },
        "declared_capabilities": {"chat": True, "multi_turn": True, "openai_compatible": True, "black_box": True},
    }
    response = httpx.post(f"{API}/api/targets", json=payload, timeout=60)
    response.raise_for_status()
    target_id = response.json()["target"]["id"]
    httpx.post(f"{API}/api/targets/{target_id}/health-check", timeout=60).raise_for_status()
    httpx.post(f"{API}/api/targets/{target_id}/discover-capabilities", timeout=60).raise_for_status()
    print(target_id)


if __name__ == "__main__":
    main()
