import os

import httpx

API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")


def main() -> None:
    response = httpx.post(f"{API}/api/demo/register-enterprise-assist", timeout=60)
    response.raise_for_status()
    data = response.json()
    print(data["target"]["id"])


if __name__ == "__main__":
    main()
