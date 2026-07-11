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
        "maximum_requests": int(os.getenv("FRAMEWORK_MAX_REQUESTS", "20")),
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
