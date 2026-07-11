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
        if "-EXEC-" in assessment_id or assessment_id.endswith(".evidence"):
            raise ValueError("Requested id is an execution evidence artifact, not an assessment result")
        path = self.evidence_dir / f"{assessment_id}.json"
        return AssessmentResult.model_validate_json(path.read_text(encoding="utf-8"))

    def list_results(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(self.evidence_dir.glob("ASM-*.json"), reverse=True):
            if "-EXEC-" in path.stem or path.stem.endswith(".evidence"):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                scope = data.get("scope") or {}
                if "scope" not in data or "target_mode" not in data:
                    continue
                rows.append(
                    {
                        "id": data.get("id", path.stem),
                        "target": scope.get("target_name") or scope.get("assessment_name") or "Unknown target",
                        "mode": data.get("target_mode", data.get("mode", "unknown")),
                        "findings": len(data.get("findings", [])),
                        "completed_at": data.get("completed_at"),
                    }
                )
            except Exception as exc:
                rows.append(
                    {
                        "id": path.stem,
                        "target": "Unreadable native assessment",
                        "mode": "needs_review",
                        "findings": 0,
                        "completed_at": None,
                        "error": str(exc),
                    }
                )
        return rows


def write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
