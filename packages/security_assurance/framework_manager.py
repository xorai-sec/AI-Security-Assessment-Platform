from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .framework_models import FrameworkAssessmentRequest, FrameworkAssessmentResult, FrameworkDefinition
from .target_manager import TargetManager
from .target_models import TargetMessageRequest


class FrameworkManager:
    def __init__(self, root: Path, target_manager: TargetManager) -> None:
        self.root = root
        self.target_manager = target_manager
        self.result_dir = root / "data" / "framework-results"
        self.result_dir.mkdir(parents=True, exist_ok=True)
        self.frameworks = {
            "native": FrameworkDefinition(id="native", name="native", worker_url=os.getenv("NATIVE_WORKER_URL", "http://native-worker:8091"), enabled=True),
            "garak": FrameworkDefinition(id="garak", name="garak", worker_url=os.getenv("GARAK_WORKER_URL", "http://garak-worker:8092"), enabled=os.getenv("FRAMEWORK_GARAK_ENABLED", "true").lower() == "true"),
            "pyrit": FrameworkDefinition(id="pyrit", name="pyrit", worker_url=os.getenv("PYRIT_WORKER_URL", "http://pyrit-worker:8093"), enabled=os.getenv("FRAMEWORK_PYRIT_ENABLED", "true").lower() == "true"),
            "deepteam": FrameworkDefinition(id="deepteam", name="deepteam", worker_url=os.getenv("DEEPTEAM_WORKER_URL", "http://deepteam-worker:8094"), enabled=os.getenv("FRAMEWORK_DEEPTEAM_ENABLED", "true").lower() == "true"),
            "promptfoo": FrameworkDefinition(id="promptfoo", name="promptfoo", worker_url=os.getenv("PROMPTFOO_WORKER_URL", "http://promptfoo-worker:8095"), enabled=os.getenv("FRAMEWORK_PROMPTFOO_ENABLED", "true").lower() == "true"),
        }

    def _model_roles(self, request: FrameworkAssessmentRequest, target_model: str) -> dict[str, Any]:
        attacker = request.attacker_model or os.getenv("OLLAMA_ATTACKER_MODEL") or os.getenv("ATTACKER_MODEL") or target_model
        judge = request.judge_model or os.getenv("OLLAMA_JUDGE_MODEL") or os.getenv("JUDGE_MODEL") or target_model
        resolved_target = request.target_model or target_model
        same_model = len({resolved_target, attacker, judge}) < 3
        warning = None
        if same_model and not request.allow_same_model_eval:
            warning = (
                "Evaluation bias warning: target, attacker, and/or judge model roles share the same model. "
                "Use separate Ollama models for stronger assessment confidence."
            )
        return {
            "target_model": resolved_target,
            "attacker_model": attacker,
            "judge_model": judge,
            "allow_same_model_eval": request.allow_same_model_eval,
            "bias_warning": warning,
        }

    def list_frameworks(self) -> list[FrameworkDefinition]:
        return list(self.frameworks.values())

    def health(self) -> dict[str, Any]:
        rows = {}
        for framework_id, framework in self.frameworks.items():
            try:
                response = httpx.get(f"{framework.worker_url}/health", timeout=20)
                response.raise_for_status()
                data = response.json()
                framework.health = data.get("status", "unknown")
                framework.version = data.get("version")
                framework.last_error = None
                framework.last_health_check = datetime.now(timezone.utc)
                rows[framework_id] = data
            except Exception as exc:
                framework.health = "unhealthy"
                framework.last_error = str(exc)
                framework.last_health_check = datetime.now(timezone.utc)
                rows[framework_id] = framework.model_dump(mode="json")
        return rows

    def capabilities(self) -> dict[str, Any]:
        rows = {}
        for framework_id, framework in self.frameworks.items():
            try:
                response = httpx.get(f"{framework.worker_url}/capabilities", timeout=20)
                response.raise_for_status()
                rows[framework_id] = response.json()
                framework.capabilities = [item.get("name", "") for item in rows[framework_id].get("capabilities", []) if item.get("supported")]
            except Exception as exc:
                rows[framework_id] = {"capabilities": [], "error": str(exc)}
        return rows

    def run_assessment(self, request: FrameworkAssessmentRequest, api_base_url: str) -> FrameworkAssessmentResult:
        target = self.target_manager.get_target(request.target_id)
        if not request.written_authorization_confirmed or not target.authorization_confirmed:
            raise ValueError("Written authorization must be confirmed")
        if not target.enabled:
            raise ValueError(f"Target is disabled: {target.disabled_reason}")

        result = FrameworkAssessmentResult(target_id=target.id, frameworks=request.frameworks)
        model_roles = self._model_roles(request, target.model_name)
        if model_roles.get("bias_warning"):
            result.warnings.append(model_roles["bias_warning"])
        for framework_id in request.frameworks:
            framework = self.frameworks.get(framework_id)
            if not framework:
                result.errors.append(f"Unknown framework: {framework_id}")
                continue
            if not framework.enabled:
                result.errors.append(f"Framework disabled: {framework_id}")
                continue
            execution_id = f"{result.id}-{framework_id}"
            payload = {
                "execution_id": execution_id,
                "assessment_id": result.id,
                "campaign_id": f"CMP-{framework_id}",
                "target": {
                    "target_id": target.id,
                    "target_type": target.target_type.value,
                    "internal_proxy_url": f"{api_base_url.rstrip('/')}/internal/targets/{target.id}/message",
                    "visibility": target.visibility.value,
                    "model_name": model_roles["target_model"],
                },
                "objective": request.objective,
                "category": request.category,
                "strategy": request.strategy,
                "profile": request.profile,
                "model_roles": model_roles,
                "limits": {
                    "maximum_requests": min(request.maximum_requests, target.max_requests),
                    "maximum_duration_seconds": min(request.maximum_duration_seconds, target.max_duration_seconds),
                    "maximum_turns": request.maximum_turns,
                    "maximum_concurrency": min(request.maximum_concurrency, target.max_concurrency),
                    "maximum_tokens": request.maximum_tokens,
                },
                "configuration": {
                    "target_metadata": {"mode": "vulnerable"},
                    "user_role": "standard_employee",
                    "probe_families": request.probe_families,
                    "promptfoo_plugins": request.promptfoo_plugins,
                    "promptfoo_strategies": request.promptfoo_strategies,
                },
                "callback_url": f"{api_base_url.rstrip('/')}/internal/framework-events",
            }
            try:
                response = httpx.post(f"{framework.worker_url}/execute", json=payload, timeout=request.maximum_duration_seconds + 30)
                response.raise_for_status()
                data = response.json()
                result.worker_results.append(data)
                result.normalized_evidence.extend(data.get("evidence", []))
                for worker_error in data.get("errors", []):
                    result.errors.append(f"{framework_id}: {worker_error}")
            except Exception as exc:
                result.errors.append(f"{framework_id}: {exc}")

        result.completed_at = datetime.now(timezone.utc)
        result.status = "succeeded" if result.normalized_evidence and not result.errors else "partially_completed" if result.normalized_evidence else "failed"
        self._save_result(result)
        return result

    def _save_result(self, result: FrameworkAssessmentResult) -> None:
        path = self.result_dir / f"{result.id}.json"
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    def list_results(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(self.result_dir.glob("MFASM-*.json"), reverse=True):
            data = FrameworkAssessmentResult.model_validate_json(path.read_text(encoding="utf-8"))
            rows.append(
                {
                    "id": data.id,
                    "target_id": data.target_id,
                    "frameworks": data.frameworks,
                    "status": data.status,
                    "evidence": len(data.normalized_evidence),
                    "errors": len(data.errors),
                    "completed_at": data.completed_at,
                }
            )
        return rows

    def load_result(self, assessment_id: str) -> FrameworkAssessmentResult:
        path = self.result_dir / f"{assessment_id}.json"
        if not path.exists():
            raise FileNotFoundError(assessment_id)
        return FrameworkAssessmentResult.model_validate_json(path.read_text(encoding="utf-8"))

    async def proxy_target_message(self, target_id: str, request_data: dict[str, Any]) -> dict[str, Any]:
        target = self.target_manager.get_target(target_id)
        adapter = __import__("packages.security_assurance.adapters.targets", fromlist=["build_target_adapter"]).build_target_adapter(target)
        response = await adapter.send_message(
            TargetMessageRequest(
                prompt=request_data["prompt"],
                session_id=request_data.get("session_id"),
                user_role=request_data.get("user_role", "standard_employee"),
                metadata=request_data.get("metadata", {}),
            )
        )
        sanitized = await adapter.sanitize_for_storage(response)
        return sanitized.model_dump(mode="json")
