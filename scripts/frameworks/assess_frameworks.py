import os
import sys

import httpx

API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")

PROFILE_DEFAULTS = {
    "quick": {"requests": 24, "turns": 8, "duration": 1800, "tokens": 4096},
    "standard": {"requests": 48, "turns": 12, "duration": 2700, "tokens": 6144},
    "comprehensive": {"requests": 96, "turns": 20, "duration": 5400, "tokens": 8192},
    "deep-owasp": {"requests": 80, "turns": 16, "duration": 7200, "tokens": 4096},
    "deep-owasp-4h": {"requests": 400, "turns": 32, "duration": 14400, "tokens": 4096},
    "deep-owasp-large": {"requests": 200000, "turns": 64, "duration": 172800, "tokens": 4096},
}


def find_target() -> str:
    targets = httpx.get(f"{API}/api/targets", timeout=30).json().get("targets", [])
    enabled = [target for target in targets if target.get("enabled")]
    if not enabled:
        raise SystemExit("No enabled target found. Register EnterpriseAssist or another target first.")
    return os.getenv("TARGET_ID") or enabled[0]["id"]


def main() -> None:
    frameworks = sys.argv[1:] or os.getenv("FRAMEWORKS", "native,garak,pyrit,promptfoo").split(",")
    profile = os.getenv("PROFILE", "quick")
    defaults = PROFILE_DEFAULTS.get(profile, PROFILE_DEFAULTS["quick"])
    strict_budget = os.getenv("STRICT_FRAMEWORK_BUDGETS", "false").lower() == "true"
    configured_requests = int(os.getenv("FRAMEWORK_MAX_REQUESTS", str(defaults["requests"])))
    configured_turns = int(os.getenv("FRAMEWORK_MAX_TURNS", str(defaults["turns"])))
    configured_duration = int(os.getenv("FRAMEWORK_MAX_DURATION_SECONDS", str(defaults["duration"])))
    configured_tokens = int(os.getenv("FRAMEWORK_MAX_TOKENS", str(defaults["tokens"])))
    if not strict_budget and os.getenv("FRAMEWORK_EXECUTION_MODE", "parallel") == "chained":
        configured_requests = max(configured_requests, defaults["requests"])
        configured_turns = max(configured_turns, defaults["turns"])
        configured_duration = max(configured_duration, defaults["duration"])
        configured_tokens = max(configured_tokens, defaults["tokens"])
    payload = {
        "target_id": find_target(),
        "frameworks": [framework.strip() for framework in frameworks if framework.strip()],
        "objective": "Authorized multi-framework AI security assessment",
        "category": "multi_framework",
        "execution_mode": os.getenv("FRAMEWORK_EXECUTION_MODE", "parallel"),
        "strategy": os.getenv("FRAMEWORK_STRATEGY", "baseline"),
        "profile": profile,
        "target_model": os.getenv("OLLAMA_TARGET_MODEL") or os.getenv("TARGET_MODEL") or "qwen3:4b",
        "attacker_model": os.getenv("OLLAMA_ATTACKER_MODEL") or os.getenv("ATTACKER_MODEL") or "qwen3:14b",
        "judge_model": os.getenv("OLLAMA_JUDGE_MODEL") or os.getenv("JUDGE_MODEL") or "gpt-oss:20b",
        "allow_same_model_eval": os.getenv("ALLOW_SAME_MODEL_EVAL", "false").lower() == "true",
        "maximum_requests": configured_requests,
        "maximum_duration_seconds": configured_duration,
        "maximum_turns": configured_turns,
        "maximum_concurrency": int(os.getenv("FRAMEWORK_MAX_CONCURRENCY", "1")),
        "maximum_tokens": configured_tokens,
        "probe_families": [item.strip() for item in os.getenv("PROBE_FAMILIES", "").split(",") if item.strip()],
        "promptfoo_plugins": [item.strip() for item in os.getenv("PROMPTFOO_PLUGINS", "").split(",") if item.strip()],
        "promptfoo_strategies": [item.strip() for item in os.getenv("PROMPTFOO_STRATEGIES", "").split(",") if item.strip()],
        "adaptive_minimum_frameworks": int(os.getenv("ADAPTIVE_MINIMUM_FRAMEWORKS", "3")),
        "continue_on_framework_error": os.getenv("CONTINUE_ON_FRAMEWORK_ERROR", "true").lower() == "true",
        "written_authorization_confirmed": True,
    }
    timeout = max(configured_duration + 900, 1800)
    response = httpx.post(f"{API}/api/assessments/frameworks", json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    print(f"{data['id']} status={data['status']} evidence={len(data['normalized_evidence'])} errors={len(data['errors'])}")
    for error in data["errors"]:
        print("ERROR", error)
    sys.exit(0 if data["normalized_evidence"] else 1)


if __name__ == "__main__":
    main()
