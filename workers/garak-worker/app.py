from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from workers.common.advanced import command_capture, write_json
from workers.common.artifacts import run_artifacts
from workers.common.base_runner import BaseFrameworkRunner
from workers.common.normalization import evidence_hash
from workers.common.protocol.schemas import (
    FrameworkExecutionRequest,
    FrameworkExecutionResult,
    NormalizedFrameworkEvidence,
    WorkerCapability,
    WorkerHealth,
)
from workers.common.server import create_worker_app


GARAK_GENERATOR = "target_proxy.TargetProxyGenerator"
GARAK_GENERATOR_CLASS = "garak.generators.target_proxy.TargetProxyGenerator"
DEFAULT_PROBES = {
    "quick": "dan.AutoDANCached,goodside.Tag,promptinject.HijackLongPrompt",
    "standard": "dan.AutoDANCached,dan.DanInTheWild,goodside.Tag,promptinject.HijackLongPrompt,encoding.InjectBase64",
    "comprehensive": "dan.AutoDANCached,dan.DanInTheWild,goodside.Tag,promptinject.HijackLongPrompt,encoding.InjectBase64,leakreplay.GuardianCloze,realtoxicityprompts.RTPBlank,malwaregen.TopLevel",
    "deep-owasp-4h": "dan.AutoDANCached,dan.DanInTheWild,goodside.Tag,promptinject.HijackLongPrompt,encoding.InjectBase64,leakreplay.GuardianCloze",
    "deep-owasp-large": "dan.AutoDANCached,dan.DanInTheWild,goodside.Tag,promptinject.HijackLongPrompt,encoding.InjectBase64,leakreplay.GuardianCloze,realtoxicityprompts.RTPBlank,malwaregen.TopLevel",
}


def _message_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        if "text" in message:
            return str(message.get("text") or "")
        content = message.get("content")
        if isinstance(content, dict):
            return str(content.get("text") or "")
        if isinstance(content, str):
            return content
    return ""


def _conversation_prompt(prompt: Any) -> str:
    if isinstance(prompt, dict):
        turns = prompt.get("turns") or []
        for turn in reversed(turns):
            if turn.get("role") == "user":
                return _message_text(turn)
    return _message_text(prompt)


class GarakRunner(BaseFrameworkRunner):
    framework_name = "garak"
    package_name = "garak"

    def _garak_discovery(self) -> dict[str, Any]:
        return {
            "probes": command_capture(["python", "-m", "garak", "--list_probes"], timeout=45),
            "detectors": command_capture(["python", "-m", "garak", "--list_detectors"], timeout=45),
            "generators": command_capture(["python", "-m", "garak", "--list_generators"], timeout=45),
            "version": self.detected_version(),
        }

    async def health(self) -> WorkerHealth:
        base = await super().health()
        if base.status != "healthy":
            return base
        plugin = command_capture(
            ["python", "-m", "garak", "--plugin_info", f"generators.{GARAK_GENERATOR}"],
            timeout=30,
        )
        if plugin["returncode"] != 0:
            return WorkerHealth(
                framework=self.framework_name,
                status="unhealthy",
                version=base.version,
                message=f"target proxy generator unavailable: {plugin['stderr'][-500:] or plugin['stdout'][-500:]}",
            )
        return WorkerHealth(
            framework=self.framework_name,
            status="healthy",
            version=base.version,
            message=f"garak CLI and {GARAK_GENERATOR_CLASS} available",
        )

    async def capabilities(self) -> list[WorkerCapability]:
        discovery = self._garak_discovery()
        return [
            WorkerCapability(name="real_cli_discovery", supported=discovery["probes"]["returncode"] == 0, detail="python -m garak --list_probes"),
            WorkerCapability(name="official_generator_loader", supported=True, detail=GARAK_GENERATOR_CLASS),
            WorkerCapability(name="official_probe_execution", supported=True, detail="python -m garak --probes ..."),
            WorkerCapability(name="official_detector_execution", supported=True, detail="garak probewise/PxD harness detectors"),
            WorkerCapability(name="native_jsonl_artifacts", supported=True, detail="unmodified garak .report.jsonl"),
        ]

    def _probe_spec(self, request: FrameworkExecutionRequest) -> str:
        configured = request.configuration.get("probe_families") or []
        probes = list(configured) if configured else DEFAULT_PROBES.get(request.profile, DEFAULT_PROBES["quick"]).split(",")
        # The API accepts high-level probe-family labels (for example
        # ``prompt_injection``), but Garak's CLI requires concrete module
        # names such as ``promptinject.HijackLongPrompt``.  Never pass labels
        # through to Garak: they are treated as unknown probes and produce an
        # empty report, which incorrectly makes the whole assessment partial.
        concrete = [str(probe).strip() for probe in probes if "." in str(probe).strip()]
        if not concrete:
            concrete = DEFAULT_PROBES.get(request.profile, DEFAULT_PROBES["quick"]).split(",")
        probes = concrete
        # HijackLongPrompt expands to hundreds of requests and is unsuitable for
        # short adaptive stages. Select it only when the stage has enough wall
        # time and request budget; this keeps profile/mode changes safe without
        # requiring operators to know Garak's internal probe cardinalities.
        long_probe = "promptinject.HijackLongPrompt"
        enough_budget = request.limits.maximum_duration_seconds >= 1200 and request.limits.maximum_requests >= 16
        if long_probe in probes and not enough_budget:
            probes.remove(long_probe)
        return ",".join(probes)

    def _write_generator_options(self, request: FrameworkExecutionRequest, traffic_path: Path, run_dir: Path) -> Path:
        options = {
            "target_proxy": {
                "TargetProxyGenerator": {
                    "api_base_url": self.proxy_base_url,
                    "target_id": request.target.target_id,
                    "execution_id": request.execution_id,
                    "campaign_id": request.campaign_id,
                    "target_proxy_secret": self.proxy.token,
                    "user_role": request.configuration.get("user_role", "standard_employee"),
                    "request_timeout": min(120, max(10, request.limits.maximum_duration_seconds)),
                    "traffic_path": str(traffic_path),
                }
            }
        }
        return write_json(run_dir / "generator-options.json", options)

    def _run_garak(self, request: FrameworkExecutionRequest, options_path: Path, report_prefix: Path) -> dict[str, Any]:
        probe_spec = self._probe_spec(request)
        probe_count = max(1, len([item for item in probe_spec.split(",") if item]))
        # Use the assessment request budget instead of silently sampling one
        # generation per probe. Keep concurrency bounded, but spend the deep
        # profile budget on independent generations for reproducibility.
        generations = max(1, min(8, request.limits.maximum_requests // probe_count))
        command = [
            "python",
            "-m",
            "garak",
            "--model_type",
            GARAK_GENERATOR,
            "--model_name",
            request.target.target_id,
            "--generator_option_file",
            str(options_path),
            "--probes",
            probe_spec,
            "--report_prefix",
            str(report_prefix),
            "--parallel_requests",
            str(max(1, min(2, request.limits.maximum_concurrency))),
            "--parallel_attempts",
            "1",
            "--generations",
            str(generations),
            "--skip_unknown",
        ]
        started = datetime.now(timezone.utc)
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=request.limits.maximum_duration_seconds,
            )
            return {
                "command": command,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "started_at": started.isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return {
                "command": command,
                "returncode": -1,
                "stdout": stdout,
                "stderr": stderr or f"garak timed out after {request.limits.maximum_duration_seconds}s",
                "started_at": started.isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }

    def _report_path(self, report_prefix: Path) -> Path:
        return Path(str(report_prefix) + ".report.jsonl")

    def _discover_report_path(self, request: FrameworkExecutionRequest, report_prefix: Path, cli_result: dict[str, Any]) -> Path:
        expected = self._report_path(report_prefix)
        if expected.exists():
            return expected
        candidates = sorted(
            self.artifact_root.glob(f"{request.execution_id}*.report.jsonl"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            return candidates[0]
        text = "\n".join([str(cli_result.get("stdout") or ""), str(cli_result.get("stderr") or "")])
        for match in re.findall(r"(/[^ \n\r\t]+\.report\.jsonl)", text):
            path = Path(match)
            if path.exists():
                return path
        return expected

    def _load_report_rows(self, report_path: Path) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not report_path.exists():
            return rows
        with report_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    rows.append({"entry_type": "unparsed", "line": line})
        return rows

    def _normalise_report(
        self,
        request: FrameworkExecutionRequest,
        rows: list[dict[str, Any]],
        report_path: Path,
        command_line: str,
    ) -> tuple[list[NormalizedFrameworkEvidence], list[str]]:
        evidence: list[NormalizedFrameworkEvidence] = []
        plugin_ids: set[str] = {GARAK_GENERATOR_CLASS}
        eval_rows = [row for row in rows if row.get("entry_type") == "eval"]
        eval_by_probe_detector = {
            (row.get("probe"), row.get("detector")): row
            for row in eval_rows
        }
        for index, row in enumerate([item for item in rows if item.get("entry_type") == "attempt"], start=1):
            probe = row.get("probe_classname") or row.get("probe") or "unknown"
            prompt = _conversation_prompt(row.get("prompt"))
            outputs = row.get("outputs") or []
            response = "\n\n".join(_message_text(output) for output in outputs if output is not None)
            detector_results = row.get("detector_results") or {}
            detector = ",".join(sorted(detector_results.keys())) or None
            plugin_ids.add(f"garak.probes.{probe}" if not str(probe).startswith("garak.") else str(probe))
            for detector_name in detector_results:
                plugin_ids.add(f"garak.detectors.{detector_name}" if not str(detector_name).startswith("garak.") else str(detector_name))
            scores = [
                float(score)
                for score_list in detector_results.values()
                for score in score_list
                if isinstance(score, int | float)
            ]
            confirmed = any(score > 0 for score in scores)
            confidence = max(scores) if scores else 0.0
            evaluator_results = [
                {
                    "detector": detector_name,
                    "scores": score_list,
                    "garak_eval": eval_by_probe_detector.get((probe, detector_name)),
                }
                for detector_name, score_list in detector_results.items()
            ]
            artifact_row = {
                "framework": self.framework_name,
                "native_report_row": row,
                "native_report_path": str(report_path),
                "command": command_line,
            }
            evidence.append(
                NormalizedFrameworkEvidence(
                    execution_id=f"{request.execution_id}-{index}",
                    assessment_id=request.assessment_id,
                    campaign_id=request.campaign_id,
                    framework=self.framework_name,
                    framework_version=self.detected_version(),
                    worker_version="0.3.0",
                    target_id=request.target.target_id,
                    target_type=request.target.target_type,
                    model_name=request.model_roles.target_model or request.target.model_name,
                    attacker_model=request.model_roles.attacker_model,
                    judge_model=request.model_roles.judge_model,
                    profile=request.profile,
                    visibility=request.target.visibility,
                    category=request.category,
                    objective=request.objective,
                    strategy=request.strategy,
                    probe=f"garak.probes.{probe}" if not str(probe).startswith("garak.") else str(probe),
                    detector=detector,
                    vulnerability=probe,
                    attack_method="garak-native-probe",
                    prompt=prompt,
                    response=response,
                    conversation_trace=[{"role": "user", "content": prompt}, {"role": "assistant", "content": response}],
                    evaluator_results=evaluator_results,
                    raw_score=confidence,
                    success=confirmed,
                    candidate=True,
                    confirmed=confirmed,
                    confidence=confidence,
                    native_engine_invoked=True,
                    native_command_or_api=command_line,
                    native_framework_version=self.detected_version(),
                    native_artifact_path=str(report_path),
                    native_plugin_identifiers=sorted(plugin_ids),
                    fallback_used=False,
                    fallback_reason=None,
                    evidence_limitations=[request.model_roles.bias_warning] if request.model_roles.bias_warning else [],
                    bias_warning=request.model_roles.bias_warning,
                    request_count=1,
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                    stop_reason="garak_native_report_attempt",
                    raw_artifact_reference=str(report_path),
                    evidence_hash=evidence_hash(artifact_row),
                )
            )
        return evidence, sorted(plugin_ids)

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        started = datetime.now(timezone.utc)
        discovery = self._garak_discovery()
        artifacts = run_artifacts(self.artifact_root, request.execution_id)
        discovery_path = write_json(artifacts.path("discovery.json"), discovery)
        traffic_path = artifacts.path("target-proxy-traffic.jsonl")
        options_path = self._write_generator_options(request, traffic_path, artifacts.root)
        report_prefix = artifacts.path("report")
        cli_result = self._run_garak(request, options_path, report_prefix)
        cli_path = write_json(artifacts.path("command.json"), cli_result)
        stdout_path = artifacts.write_text("stdout.log", str(cli_result.get("stdout") or ""))
        stderr_path = artifacts.write_text("stderr.log", str(cli_result.get("stderr") or ""))
        garak_log = Path.home() / ".local" / "share" / "garak" / "garak.log"
        log_copy_path = artifacts.path("garak.log")
        if garak_log.exists():
            shutil.copyfile(garak_log, log_copy_path)
        report_path = self._discover_report_path(request, report_prefix, cli_result)
        rows = self._load_report_rows(report_path)
        command_line = " ".join(cli_result["command"])
        evidence, plugin_ids = self._normalise_report(request, rows, report_path, command_line)
        errors = []
        if cli_result["returncode"] != 0:
            errors.append(f"garak CLI returned {cli_result['returncode']}: {cli_result['stderr'] or cli_result['stdout']}")
        if not report_path.exists():
            errors.append(
                "Native garak report was not created at "
                f"{report_path}. CLI diagnostics saved at {cli_path}; stdout={cli_result.get('stdout', '')[-1000:]!r}; "
                f"stderr={cli_result.get('stderr', '')[-1000:]!r}"
            )
        if not evidence:
            errors.append("Native garak report contained no attempt rows to normalize")
        status = "succeeded" if evidence and not errors else "partially_completed" if evidence else "failed"
        return FrameworkExecutionResult(
            execution_id=request.execution_id,
            framework=self.framework_name,
            status=status,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            raw_artifacts=[
                str(discovery_path),
                str(options_path),
                str(cli_path),
                str(stdout_path),
                str(stderr_path),
                str(report_path),
                str(traffic_path),
                str(log_copy_path),
            ],
            evidence=evidence,
            errors=errors,
            native_engine_invoked=bool(evidence) and report_path.exists() and cli_result["returncode"] == 0,
            native_command_or_api=command_line,
            native_framework_version=self.detected_version(),
            native_artifact_path=str(report_path),
            native_plugin_identifiers=plugin_ids,
            fallback_used=False,
            fallback_reason=None,
        )


app = create_worker_app(GarakRunner())
