import os
import sys

import httpx

API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")


def main() -> None:
    targets = httpx.get(f"{API}/api/targets", timeout=30).json().get("targets", [])
    failures = 0
    for target in targets:
        target_id = target["id"]
        validation = httpx.post(f"{API}/api/targets/{target_id}/validate", timeout=30)
        health = httpx.post(f"{API}/api/targets/{target_id}/health-check", timeout=30)
        print(f"{target_id} validation={validation.status_code} health={health.status_code}")
        if validation.status_code >= 400 or health.status_code >= 400:
            failures += 1
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
