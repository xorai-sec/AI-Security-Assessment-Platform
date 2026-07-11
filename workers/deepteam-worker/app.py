from __future__ import annotations

import pkgutil
from datetime import datetime, timezone
from typing import Any

from workers.common.advanced import framework_evidence, select_cases, write_json
from workers.common.base_runner import BaseFrameworkRunner
from workers.common.protocol.schemas import FrameworkExecutionRequest, FrameworkExecutionResult, WorkerCapability
from workers.common.server import create_worker_app


DEEPTEAM_ENHANCEMENTS = {
    "prompt_leakage": "jailbreaking.linear_probe",
    "prompt_injection": "prompt_injection.context_override",
    "unauthorized_retrieval": "data_leakage.role_play",
    "unauthorized_tool_execution": "excessive_agency.permission_escalation",
    "confirmation_bypass": "human_oversight.bypass_confirmation",
    "memory_isolation": "privacy.cross_session_memory",
}


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
            WorkerCapability(name="vulnerability_discovery", supported=True, detail=f"package status: {discovery['status']}"),
            WorkerCapability(name="attack_enhancements", supported=True, detail=", ".join(sorted(set(DEEPTEAM_ENHANCEMENTS.values())))),
            WorkerCapability(name="target_callback", supported=True),
            WorkerCapability(name="evaluator_outputs", supported=True),
            WorkerCapability(name="version_aware_discovery", supported=discovery["status"] == "available"),
        ]

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        started = datetime.now(timezone.utc)
        discovery_path = write_json(self.artifact_root / f"{request.execution_id}-deepteam-discovery.json", self._discovery())
        cases = select_cases(request, request.configuration.get("probe_families", []))
        rows = []
        evidence = []
        errors = []
        for index, case in enumerate(cases, start=1):
            enhancement = DEEPTEAM_ENHANCEMENTS.get(case.category, "generic.redteam.enhancement")
            enhanced_prompt = f"[{enhancement}] {case.prompt}"
            try:
                response = await self.proxy.send_message(
                    request.target.target_id,
                    request.execution_id,
                    request.campaign_id,
                    enhanced_prompt,
                    session_id=f"{request.execution_id}-deepteam-{index}",
                    user_role=request.configuration.get("user_role", "standard_employee"),
                    metadata={**request.configuration.get("target_metadata", {}), "framework": "deepteam", "vulnerability": case.vulnerability, "enhancement": enhancement},
                )
            except Exception as exc:
                errors.append(str(exc))
                continue
            evaluator_output = {
                "deepteam_vulnerability": case.vulnerability,
                "deepteam_attack_enhancement": enhancement,
                "deepteam_attack_id": f"deepteam.{case.category}.{index}",
                "target_callback": request.target.internal_proxy_url,
            }
            rows.append({"case": case.__dict__, "enhancement": enhancement, "prompt": enhanced_prompt, "response": response, "evaluator": evaluator_output})
            normalized = framework_evidence(
                request=request,
                framework=self.framework_name,
                framework_version=self.detected_version(),
                case=case,
                index=index,
                prompt=enhanced_prompt,
                response=response,
                artifact_path=self.artifact_root / f"{request.execution_id}-deepteam-results.json",
                evaluator_extra=evaluator_output,
            )
            normalized.vulnerability = case.vulnerability
            normalized.attack_method = enhancement
            evidence.append(normalized)
        results_path = write_json(self.artifact_root / f"{request.execution_id}-deepteam-results.json", {"request": request.model_dump(mode="json"), "results": rows})
        status = "succeeded" if evidence and not errors else "partially_completed" if evidence else "failed"
        return FrameworkExecutionResult(
            execution_id=request.execution_id,
            framework=self.framework_name,
            status=status,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            raw_artifacts=[str(discovery_path), str(results_path)],
            evidence=evidence,
            errors=errors,
        )


app = create_worker_app(DeepTeamRunner())
