import os
import sys

import httpx

API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")


def run(framework: str) -> bool:
    response = httpx.post(f"{API}/api/frameworks/self-test/{framework}", timeout=60)
    print(framework, response.status_code, response.text[:800])
    return response.status_code < 400 and '"status":"healthy"' in response.text.replace(" ", "")


def main() -> None:
    frameworks = sys.argv[1:] or ["native", "garak", "pyrit", "promptfoo", "deepteam"]
    ok = all(run(framework) for framework in frameworks)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
