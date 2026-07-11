from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AssessmentResult


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence_dir = root / "data" / "evidence"
        self.report_dir = root / "data" / "reports"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, name: str, data: Any) -> Path:
        path = self.evidence_dir / name
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def save_result(self, result: AssessmentResult) -> Path:
        return self.save_json(f"{result.id}.json", result.model_dump(mode="json"))

    def load_result(self, assessment_id: str) -> AssessmentResult:
        path = self.evidence_dir / f"{assessment_id}.json"
        return AssessmentResult.model_validate_json(path.read_text(encoding="utf-8"))

    def list_results(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(self.evidence_dir.glob("ASM-*.json"), reverse=True):
            data = json.loads(path.read_text(encoding="utf-8"))
            rows.append(
                {
                    "id": data["id"],
                    "target": data["scope"]["target_name"],
                    "mode": data["target_mode"],
                    "findings": len(data.get("findings", [])),
                    "completed_at": data.get("completed_at"),
                }
            )
        return rows


def write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path

