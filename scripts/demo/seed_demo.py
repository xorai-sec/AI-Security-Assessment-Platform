import httpx


def main() -> None:
    response = httpx.post("http://127.0.0.1:8080/api/demo/seed", timeout=30)
    response.raise_for_status()
    data = response.json()
    print(f"Seeded organization: {data['organization']['name']}")
    print(f"Seeded AI system: {data['ai_system']['name']}")


if __name__ == "__main__":
    main()

