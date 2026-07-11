from pathlib import Path


def main() -> None:
    reports = sorted(Path("data/reports").glob("ASM-*.md"), reverse=True)
    if not reports:
        raise SystemExit("No reports found. Run make demo-assess first.")
    latest = reports[0]
    print(latest)
    print(latest.read_text(encoding="utf-8")[:4000])


if __name__ == "__main__":
    main()

