import httpx


def run(mode: str) -> str:
    response = httpx.post(
        "http://127.0.0.1:8080/api/assessments/demo",
        json={"target_url": "http://enterprise-assist:8090" if False else "http://127.0.0.1:8090", "mode": mode},
        timeout=180,
    )
    response.raise_for_status()
    data = response.json()
    print(f"{mode}: {data['id']} findings={len(data['findings'])} reports={data['reports']}")
    return data["id"]


def main() -> None:
    vulnerable_id = run("vulnerable")
    hardened_id = run("hardened")
    print(f"Vulnerable assessment: {vulnerable_id}")
    print(f"Hardened assessment: {hardened_id}")


if __name__ == "__main__":
    main()

