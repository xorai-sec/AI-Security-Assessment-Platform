import os

import httpx


API = os.getenv("AISEC_API_URL", "http://127.0.0.1:8080")


def main() -> None:
    targets = [target for target in httpx.get(f"{API}/api/targets", timeout=30).json().get("targets", []) if target.get("enabled")]
    if len(targets) < 2:
        raise SystemExit("At least two enabled targets are required for comparison.")
    rows = []
    for target in targets[:2]:
        response = httpx.post(
            f"{API}/api/assessments/target",
            json={"target_id": target["id"], "written_authorization_confirmed": True, "max_requests": 20},
            timeout=240,
        )
        response.raise_for_status()
        result = response.json()
        rows.append((target["target_name"], result["id"], len(result["executions"]), len(result["findings"])))
    for row in rows:
        print(f"{row[0]} assessment={row[1]} executions={row[2]} findings={row[3]}")


if __name__ == "__main__":
    main()
