import os
import sys

import httpx


API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")


def find_target() -> str:
    targets = httpx.get(f"{API}/api/targets", timeout=30).json().get("targets", [])
    enabled = [target for target in targets if target.get("enabled")]
    if not enabled:
        raise SystemExit("No enabled target found. Register EnterpriseAssist or another target first.")
    return os.getenv("TARGET_ID") or enabled[0]["id"]


def main() -> None:
    frameworks = sys.argv[1:] or os.getenv("FRAMEWORKS", "native,garak,pyrit,promptfoo,deepteam").split(",")
    payload = {
        "target_id": find_target(),
        "frameworks": [framework.strip() for framework in frameworks if framework.strip()],
        "objective": "Authorized multi-framework AI security assessment",
        "category": "multi_framework",
        "strategy": "baseline",
        "profile": os.getenv("PROFILE", "quick"),
        "target_model": os.getenv("OLLAMA_TARGET_MODEL") or os.getenv("TARGET_MODEL"),
        "attacker_model": os.getenv("OLLAMA_ATTACKER_MODEL") or os.getenv("ATTACKER_MODEL"),
        "judge_model": os.getenv("OLLAMA_JUDGE_MODEL") or os.getenv("JUDGE_MODEL"),
        "allow_same_model_eval": os.getenv("ALLOW_SAME_MODEL_EVAL", "false").lower() == "true",
        "maximum_requests": int(os.getenv("FRAMEWORK_MAX_REQUESTS", "20")),
        "maximum_duration_seconds": int(os.getenv("FRAMEWORK_MAX_DURATION_SECONDS", "900")),
        "maximum_turns": int(os.getenv("FRAMEWORK_MAX_TURNS", "5")),
        "maximum_concurrency": int(os.getenv("FRAMEWORK_MAX_CONCURRENCY", "1")),
        "maximum_tokens": int(os.getenv("FRAMEWORK_MAX_TOKENS", "2048")),
        "probe_families": [item.strip() for item in os.getenv("PROBE_FAMILIES", "").split(",") if item.strip()],
        "promptfoo_plugins": [item.strip() for item in os.getenv("PROMPTFOO_PLUGINS", "").split(",") if item.strip()],
        "promptfoo_strategies": [item.strip() for item in os.getenv("PROMPTFOO_STRATEGIES", "").split(",") if item.strip()],
        "written_authorization_confirmed": True,
    }
    response = httpx.post(f"{API}/api/assessments/frameworks", json=payload, timeout=1200)
    response.raise_for_status()
    data = response.json()
    print(f"{data['id']} status={data['status']} evidence={len(data['normalized_evidence'])} errors={len(data['errors'])}")
    for error in data["errors"]:
        print("ERROR", error)
    sys.exit(0 if data["normalized_evidence"] else 1)


if __name__ == "__main__":
    main()
