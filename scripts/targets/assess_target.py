import os
import sys

import httpx

API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")


def main() -> None:
    target_id = os.getenv("TARGET_ID") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not target_id:
        targets = httpx.get(f"{API}/api/targets", timeout=30).json().get("targets", [])
        targets = [target for target in targets if target.get("enabled")]
        if not targets:
            raise SystemExit("No enabled target found. Register and validate a target first.")
        target_id = targets[0]["id"]
    response = httpx.post(
        f"{API}/api/assessments/target",
        json={"target_id": target_id, "written_authorization_confirmed": True, "max_requests": 20},
        timeout=240,
    )
    response.raise_for_status()
    data = response.json()
    print(f"{data['id']} target={target_id} executions={len(data['executions'])} findings={len(data['findings'])}")


if __name__ == "__main__":
    main()
