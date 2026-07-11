from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from workers.common.advanced import command_capture, framework_evidence, select_cases, write_json, write_jsonl
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
            WorkerCapability(name="native_jsonl_artifacts", supported=True),
            WorkerCapability(name="detector_normalization", supported=True),
            WorkerCapability(name="target_proxy_generator", supported=True, detail="Internal target proxy backed garak-compatible generator"),
        ]

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        started = datetime.now(timezone.utc)
        discovery = self._garak_discovery()
        discovery_path = write_json(self.artifact_root / f"{request.execution_id}-garak-discovery.json", discovery)
        generator_path = write_json(
            self.artifact_root / f"{request.execution_id}-target-proxy-generator.json",
            {
                "type": "garak-compatible-custom-generator",
                "target_proxy": request.target.internal_proxy_url,
                "target_id": request.target.target_id,
                "profile": request.profile,
                "model_roles": request.model_roles.model_dump(mode="json"),
                "note": "This worker calls the authorized internal target proxy and preserves garak probe/detector metadata.",
            },
        )
        cases = select_cases(request, request.configuration.get("probe_families", []))
        evidence = []
        jsonl_rows = []
        errors = []
        for index, case in enumerate(cases, start=1):
            try:
                response = await self.proxy.send_message(
                    request.target.target_id,
                    request.execution_id,
                    request.campaign_id,
                    case.prompt,
                    session_id=f"{request.execution_id}-garak-{index}",
                    user_role=request.configuration.get("user_role", "standard_employee"),
                    metadata={**request.configuration.get("target_metadata", {}), "framework": "garak", "probe": case.probe},
                )
            except Exception as exc:
                errors.append(str(exc))
                continue
            garak_probe = f"garak.probes.{case.probe}"
            garak_detector = f"garak.detectors.{case.detector or 'deterministic_canary'}"
            artifact_row = {
                "entry_type": "garak_attempt",
                "probe": garak_probe,
                "detector": garak_detector,
                "prompt": case.prompt,
                "response": response,
                "score": None,
                "profile": request.profile,
            }
            jsonl_rows.append(artifact_row)
            normalized = framework_evidence(
                request=request,
                framework=self.framework_name,
                framework_version=self.detected_version(),
                case=case,
                index=index,
                prompt=case.prompt,
                response=response,
                artifact_path=self.artifact_root / f"{request.execution_id}-garak-report.jsonl",
                evaluator_extra={"garak_probe": garak_probe, "garak_detector": garak_detector, "garak_discovery_artifact": str(discovery_path)},
            )
            normalized.probe = garak_probe
            normalized.detector = garak_detector
            evidence.append(normalized)
        report_path = write_jsonl(self.artifact_root / f"{request.execution_id}-garak-report.jsonl", jsonl_rows)
        status = "succeeded" if evidence and not errors else "partially_completed" if evidence else "failed"
        return FrameworkExecutionResult(
            execution_id=request.execution_id,
            framework=self.framework_name,
            status=status,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            raw_artifacts=[str(discovery_path), str(generator_path), str(report_path)],
            evidence=evidence,
            errors=errors,
        )


app = create_worker_app(GarakRunner())
