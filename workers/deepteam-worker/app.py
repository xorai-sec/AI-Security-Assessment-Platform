from __future__ import annotations

import pkgutil
from datetime import datetime, timezone

from workers.common.advanced import write_json
from workers.common.base_runner import BaseFrameworkRunner
from workers.common.protocol.schemas import FrameworkExecutionRequest, FrameworkExecutionResult, WorkerCapability
from workers.common.server import create_worker_app


class DeepTeamRunner(BaseFrameworkRunner):
    framework_name = "deepteam"
    package_name = "deepteam"

    def _discovery(self) -> dict[str, Any]:
        try:
            import deepteam  # type: ignore
            modules = sorted(module.name for module in pkgutil.walk_packages(deepteam.__path__, prefix="deepteam.") if any(key in module.name.lower() for key in ["vulner", "attack", "red", "eval"]))[:300]
            return {"version": self.detected_version(), "status": "available", "modules": modules}
        except Exception as exc:
            return {"version": self.detected_version(), "status": "limited", "modules": [], "error": str(exc)}

    async def capabilities(self) -> list[WorkerCapability]:
        discovery = self._discovery()
        return [
            WorkerCapability(name="vulnerability_discovery", supported=False, detail=f"native DeepTeam scan API not wired; package status: {discovery['status']}"),
            WorkerCapability(name="attack_enhancements", supported=False, detail="Requires genuine DeepTeam attack enhancement classes"),
            WorkerCapability(name="target_callback", supported=False, detail="Requires native DeepTeam target callback execution"),
            WorkerCapability(name="evaluator_outputs", supported=False, detail="Requires native DeepTeam evaluator result objects"),
            WorkerCapability(name="version_aware_discovery", supported=discovery["status"] == "available"),
        ]

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        started = datetime.now(timezone.utc)
        discovery_path = write_json(self.artifact_root / f"{request.execution_id}-deepteam-discovery.json", self._discovery())
        error = (
            "Strict native DeepTeam execution is not implemented: this worker did not invoke the installed "
            "DeepTeam scan/red-team API, vulnerability classes, attack enhancement classes, target callback, "
            "or native evaluator output objects. Discovery artifacts were saved only."
        )
        return FrameworkExecutionResult(
            execution_id=request.execution_id,
            framework=self.framework_name,
            status="failed",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            raw_artifacts=[str(discovery_path)],
            evidence=[],
            errors=[error],
            native_engine_invoked=False,
            native_command_or_api="import deepteam; pkgutil.walk_packages(deepteam.__path__)",
            native_framework_version=self.detected_version(),
            native_artifact_path=str(discovery_path),
            native_plugin_identifiers=[],
            fallback_used=False,
        )


app = create_worker_app(DeepTeamRunner())
