import os
import sys

import httpx


API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")


def main() -> None:
    response = httpx.post(f"{API}/api/frameworks/health", timeout=60)
    response.raise_for_status()
    data = response.json()["frameworks"]
    failures = 0
    for name, health in data.items():
        print(f"{name}: {health.get('status')} version={health.get('version')} message={health.get('message') or health.get('last_error')}")
        if health.get("status") not in {"healthy", "ok"}:
            failures += 1
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
