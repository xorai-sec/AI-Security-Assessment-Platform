from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone

UTC = timezone.utc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
PACKAGE_DIR = DATA / "evidence-packages"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    package_id = datetime.now(UTC).strftime("evidence-package-%Y%m%d-%H%M%S")
    package_path = PACKAGE_DIR / f"{package_id}.zip"
    source_dirs = ["evidence", "reports", "targets", "framework-results", "framework-artifacts"]
    manifest = {
        "package_id": package_id,
        "created_at": datetime.now(UTC).isoformat(),
        "sources": source_dirs,
        "redaction": "Credentials are excluded by design; files are collected from sanitized platform stores.",
        "hashes": {},
    }
    with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for source in source_dirs:
            directory = DATA / source
            if not directory.exists():
                continue
            for path in directory.rglob("*"):
                if path.is_file() and path.name != ".gitkeep":
                    relative = path.relative_to(DATA)
                    manifest["hashes"][str(relative)] = sha256(path)
                    archive.write(path, f"assessment-package/{relative}")
        archive.writestr("assessment-package/manifest.json", json.dumps(manifest, indent=2))
    print(package_path)


if __name__ == "__main__":
    main()
# ruff: noqa: E402, UP017
