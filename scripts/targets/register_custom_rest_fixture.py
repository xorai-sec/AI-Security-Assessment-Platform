import os

import httpx


API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")
BASE_URL = os.getenv("AISEC_CUSTOM_REST_FIXTURE_URL", "http://enterprise-assist:8090")


def main() -> None:
    payload = {
        "organization": "Contoso Global",
        "system_name": "Custom REST AI Fixture",
        "target_name": "Custom REST local fixture",
        "target_type": "custom_rest",
        "system_owner": "AI Platform Owner",
        "technical_owner": "AI Engineering",
        "model_provider": "local-fixture",
        "model_name": "custom-rest-fixture",
        "authorization_confirmed": True,
        "kill_switch_acknowledged": True,
        "configuration": {
            "base_url": BASE_URL,
            "health_path": "/custom-health",
            "chat_path": "/custom-chat",
            "prompt_field_path": "input.prompt",
            "user_role_field_path": "session.role",
            "session_field_path": "session.id",
            "response_text_path": "answer",
            "request_id_path": "meta.request_id",
            "telemetry_path": "trace",
            "request_json_template": {"input": {}, "session": {}},
        },
        "declared_capabilities": {"chat": True, "multi_turn": True, "grey_box": True, "black_box": False},
    }
    response = httpx.post(f"{API}/api/targets", json=payload, timeout=60)
    response.raise_for_status()
    target_id = response.json()["target"]["id"]
    httpx.post(f"{API}/api/targets/{target_id}/health-check", timeout=60).raise_for_status()
    httpx.post(f"{API}/api/targets/{target_id}/discover-capabilities", timeout=60).raise_for_status()
    print(target_id)


if __name__ == "__main__":
    main()
