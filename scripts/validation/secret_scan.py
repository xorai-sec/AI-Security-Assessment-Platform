import re
from pathlib import Path

PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)aws_secret_access_key"),
]


def main() -> None:
    roots = [Path("apps"), Path("packages"), Path("scripts"), Path("docs")]
    scanner_path = Path(__file__).resolve()
    hits = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.resolve() == scanner_path:
                continue
            if path.is_file() and path.suffix in {".py", ".md", ".ts", ".tsx", ".json", ".yml", ".yaml"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                for pattern in PATTERNS:
                    if pattern.search(text):
                        hits.append(str(path))
    if hits:
        raise SystemExit("Potential secrets found:\n" + "\n".join(sorted(set(hits))))
    print("Secret scan passed")


if __name__ == "__main__":
    main()
