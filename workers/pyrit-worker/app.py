from __future__ import annotations

import pkgutil
from datetime import datetime, timezone

from workers.common.advanced import write_json
from workers.common.base_runner import BaseFrameworkRunner
from workers.common.protocol.schemas import FrameworkExecutionRequest, FrameworkExecutionResult, WorkerCapability
from workers.common.server import create_worker_app


class PyRITRunner(BaseFrameworkRunner):
    framework_name = "pyrit"
    package_name = "pyrit"

    def _discovery(self) -> dict[str, Any]:
        try:
            import pyrit  # type: ignore
            modules = sorted(module.name for module in pkgutil.walk_packages(pyrit.__path__, prefix="pyrit.") if any(key in module.name for key in ["prompt", "score", "memory", "orchestrator", "converter"]))[:300]
            return {"version": self.detected_version(), "modules": modules, "status": "available"}
        except Exception as exc:
            return {"version": self.detected_version(), "modules": [], "status": "limited", "error": str(exc)}

    async def capabilities(self) -> list[WorkerCapability]:
        discovery = self._discovery()
        return [
            WorkerCapability(name="package_introspection", supported=discovery["status"] == "available", detail=f"{len(discovery['modules'])} pyrit modules discovered"),
            WorkerCapability(name="multi_turn_conversations", supported=False, detail="Requires official PyRIT orchestrator/executor integration"),
            WorkerCapability(name="prompt_target_proxy", supported=False, detail="No PyRIT PromptTarget subclass is invoked by this worker yet"),
            WorkerCapability(name="converters", supported=False, detail="Requires genuine PyRIT converter objects"),
            WorkerCapability(name="scorers", supported=False, detail="Requires genuine PyRIT scorer objects"),
            WorkerCapability(name="memory", supported=False, detail="Requires genuine PyRIT memory records"),
        ]

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        started = datetime.now(timezone.utc)
        discovery_path = write_json(self.artifact_root / f"{request.execution_id}-pyrit-discovery.json", self._discovery())
        error = (
            "Strict native PyRIT execution is not implemented: this worker did not create actual PyRIT "
            "PromptTarget, orchestrator/executor, memory, converter, or scorer objects. Discovery artifacts "
            "were saved only, and no simulated multi-turn loop was used."
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
            native_command_or_api="import pyrit; pkgutil.walk_packages(pyrit.__path__)",
            native_framework_version=self.detected_version(),
            native_artifact_path=str(discovery_path),
            native_plugin_identifiers=[],
            fallback_used=False,
        )


app = create_worker_app(PyRITRunner())
