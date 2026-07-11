from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from workers.common.advanced import command_capture, write_json
from workers.common.base_runner import BaseFrameworkRunner
from workers.common.protocol.schemas import FrameworkExecutionRequest, FrameworkExecutionResult, WorkerCapability, WorkerHealth
from workers.common.server import create_worker_app


class GarakRunner(BaseFrameworkRunner):
    framework_name = "garak"
    package_name = "garak"

    def _garak_discovery(self) -> dict[str, Any]:
        return {
            "probes": command_capture(["python", "-m", "garak", "--list_probes"], timeout=45),
            "detectors": command_capture(["python", "-m", "garak", "--list_detectors"], timeout=45),
            "version": self.detected_version(),
        }

    async def health(self) -> WorkerHealth:
        base = await super().health()
        if base.status != "healthy":
            return base
        probes = command_capture(["python", "-m", "garak", "--list_probes"], timeout=30)
        if probes["returncode"] != 0:
            return WorkerHealth(framework=self.framework_name, status="unhealthy", version=base.version, message=probes["stderr"][-500:])
        return WorkerHealth(framework=self.framework_name, status="healthy", version=base.version, message="garak CLI probe discovery available")

    async def capabilities(self) -> list[WorkerCapability]:
        discovery = self._garak_discovery()
        return [
            WorkerCapability(name="real_cli_discovery", supported=discovery["probes"]["returncode"] == 0, detail="python -m garak --list_probes"),
            WorkerCapability(name="probe_family_selection", supported=True, detail="configuration.probe_families"),
            WorkerCapability(name="native_jsonl_artifacts", supported=False, detail="Strict native generator/probe/detector execution is not wired yet"),
            WorkerCapability(name="detector_normalization", supported=False, detail="Requires native garak detector execution"),
            WorkerCapability(name="target_proxy_generator", supported=False, detail="No installed garak Generator subclass is invoked by this worker yet"),
        ]

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        started = datetime.now(timezone.utc)
        discovery = self._garak_discovery()
        discovery_path = write_json(self.artifact_root / f"{request.execution_id}-garak-discovery.json", discovery)
        command_or_api = "python -m garak --list_probes; python -m garak --list_detectors"
        error = (
            "Strict native garak execution is not implemented: this worker did not instantiate a real "
            "garak Generator backed by the target proxy, invoke installed Probe classes, execute Detector "
            "classes, or preserve an unmodified native garak report. Discovery artifacts were saved only."
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
            native_command_or_api=command_or_api,
            native_framework_version=self.detected_version(),
            native_artifact_path=str(discovery_path),
            native_plugin_identifiers=[],
            fallback_used=False,
        )


app = create_worker_app(GarakRunner())
