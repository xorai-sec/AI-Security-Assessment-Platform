from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class RunArtifacts:
    def __init__(self, framework_root: Path, execution_id: str) -> None:
        self.root = framework_root / execution_id
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, name: str) -> Path:
        return self.root / name

    def write_json(self, name: str, payload: Any) -> Path:
        path = self.path(name)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def write_jsonl(self, name: str, rows: list[dict[str, Any]]) -> Path:
        path = self.path(name)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, default=str) + "\n")
        return path

    def write_text(self, name: str, text: str) -> Path:
        path = self.path(name)
        path.write_text(text, encoding="utf-8")
        return path


def run_artifacts(framework_root: Path, execution_id: str) -> RunArtifacts:
    return RunArtifacts(framework_root, execution_id)
