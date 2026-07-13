from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .adaptive_planner import AdaptiveAttackPlanner, PlannerDecision
from .framework_models import FrameworkAssessmentRequest, FrameworkAssessmentResult, FrameworkDefinition
from .reporting import write_framework_reports
from .target_manager import TargetManager
from .target_models import TargetMessageRequest

CHAIN_START = "garak"
CHAIN_ORDER = ["garak", "pyrit", "promptfoo", "native"]


class FrameworkManager:
    def __init__(self, root: Path, target_manager: TargetManager) -> None:
        self.root = root
        self.target_manager = target_manager
        self.result_dir = root / "data" / "framework-results"
        self.result_dir.mkdir(parents=True, exist_ok=True)
        self.cancel_dir = root / "data" / "framework-cancel"
        self.cancel_dir.mkdir(parents=True, exist_ok=True)
        self.frameworks = {
            "native": FrameworkDefinition(id="native", name="native", worker_url=os.getenv("NATIVE_WORKER_URL", "http://native-worker:8091"), enabled=True),
            "garak": FrameworkDefinition(id="garak", name="garak", worker_url=os.getenv("GARAK_WORKER_URL", "http://garak-worker:8092"), enabled=os.getenv("FRAMEWORK_GARAK_ENABLED", "true").lower() == "true"),
            "pyrit": FrameworkDefinition(id="pyrit", name="pyrit", worker_url=os.getenv("PYRIT_WORKER_URL", "http://pyrit-worker:8093"), enabled=os.getenv("FRAMEWORK_PYRIT_ENABLED", "true").lower() == "true"),
            "deepteam": FrameworkDefinition(id="deepteam", name="deepteam", worker_url=os.getenv("DEEPTEAM_WORKER_URL", "http://deepteam-worker:8094"), enabled=os.getenv("FRAMEWORK_DEEPTEAM_ENABLED", "false").lower() == "true"),
            "promptfoo": FrameworkDefinition(id="promptfoo", name="promptfoo", worker_url=os.getenv("PROMPTFOO_WORKER_URL", "http://promptfoo-worker:8095"), enabled=os.getenv("FRAMEWORK_PROMPTFOO_ENABLED", "true").lower() == "true"),
        }
        self.planner = AdaptiveAttackPlanner(root, self.frameworks)

    def _model_roles(self, request: FrameworkAssessmentRequest, target_model: str) -> dict[str, Any]:
        attacker = request.attacker_model or os.getenv("OLLAMA_ATTACKER_MODEL") or os.getenv("ATTACKER_MODEL") or target_model
        judge = request.judge_model or os.getenv("OLLAMA_JUDGE_MODEL") or os.getenv("JUDGE_MODEL") or target_model
        resolved_target = request.target_model or target_model
        planner = os.getenv("OLLAMA_PLANNER_MODEL") or os.getenv("PLANNER_MODEL") or attacker
        embedding = os.getenv("OLLAMA_EMBEDDING_MODEL") or os.getenv("EMBEDDING_MODEL") or "nomic-embed-text"
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
            "planner_model": planner,
            "embedding_model": embedding,
            "allow_same_model_eval": request.allow_same_model_eval,
            "bias_warning": warning,
        }

    def list_frameworks(self) -> list[FrameworkDefinition]:
        return list(self.frameworks.values())

    def health(self) -> dict[str, Any]:
        rows = {}
        for framework_id, framework in self.frameworks.items():
            if not framework.enabled:
                framework.health = "disabled"
                framework.last_error = None
                framework.last_health_check = datetime.now(UTC)
                rows[framework_id] = framework.model_dump(mode="json")
                continue
            try:
                response = httpx.get(f"{framework.worker_url}/health", timeout=20)
                response.raise_for_status()
                data = response.json()
                framework.health = data.get("status", "unknown")
                framework.version = data.get("version")
                framework.last_error = None
                framework.last_health_check = datetime.now(UTC)
                rows[framework_id] = data
            except Exception as exc:
                framework.health = "unhealthy"
                framework.last_error = str(exc)
                framework.last_health_check = datetime.now(UTC)
                rows[framework_id] = framework.model_dump(mode="json")
        return rows

    def capabilities(self) -> dict[str, Any]:
        rows = {}
        for framework_id, framework in self.frameworks.items():
            if not framework.enabled:
                rows[framework_id] = {"capabilities": [], "status": "disabled"}
                framework.capabilities = []
                continue
            try:
                response = httpx.get(f"{framework.worker_url}/capabilities", timeout=20)
                response.raise_for_status()
                rows[framework_id] = response.json()
                framework.capabilities = [item.get("name", "") for item in rows[framework_id].get("capabilities", []) if item.get("supported")]
            except Exception as exc:
                rows[framework_id] = {"capabilities": [], "error": str(exc)}
        return rows

    def _build_execution_payload(
        self,
        *,
        request: FrameworkAssessmentRequest,
        result: FrameworkAssessmentResult,
        target: Any,
        framework_id: str,
        api_base_url: str,
        model_roles: dict[str, Any],
        inherited_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        planner_decision = (inherited_context or {}).get("planner_decision", {})
        selected_probe_families = planner_decision.get("selected_probes") or request.probe_families
        selected_promptfoo_plugins = planner_decision.get("selected_plugins") or request.promptfoo_plugins
        selected_promptfoo_strategies = planner_decision.get("selected_strategies") or request.promptfoo_strategies
        selected_profile = planner_decision.get("profile") or request.profile
        selected_objective = planner_decision.get("objective") or request.objective
        request_budget = int(planner_decision.get("request_budget") or request.maximum_requests)
        turn_budget = int(planner_decision.get("turn_budget") or request.maximum_turns)
        token_budget = int(planner_decision.get("token_budget") or request.maximum_tokens)
        time_budget = int(planner_decision.get("time_budget_seconds") or request.maximum_duration_seconds)
        configuration = {
            "target_metadata": {"mode": "vulnerable"},
            "user_role": "standard_employee",
            "probe_families": selected_probe_families,
            "promptfoo_plugins": selected_promptfoo_plugins,
            "promptfoo_strategies": selected_promptfoo_strategies,
            "pyrit_converters": planner_decision.get("selected_converters", []),
            "deepteam_vulnerabilities": planner_decision.get("selected_vulnerabilities", []),
            "deepteam_attacks": planner_decision.get("selected_attacks", []),
            "planner_action_type": planner_decision.get("action_type"),
            "planner_expected_confirmation_condition": planner_decision.get("expected_confirmation_condition"),
        }
        if inherited_context:
            configuration["chain_context"] = inherited_context
        return {
            "execution_id": f"{result.id}-{framework_id}",
            "assessment_id": result.id,
            "campaign_id": f"CMP-{framework_id}",
            "target": {
                "target_id": target.id,
                "target_type": target.target_type.value,
                "internal_proxy_url": f"{api_base_url.rstrip('/')}/internal/targets/{target.id}/message",
                "visibility": target.visibility.value,
                "model_name": model_roles["target_model"],
            },
            "objective": selected_objective,
            "category": request.category,
            "strategy": request.strategy,
            "profile": selected_profile,
            "model_roles": model_roles,
            "limits": {
                "maximum_requests": min(request.maximum_requests, target.max_requests, request_budget),
                "maximum_duration_seconds": min(request.maximum_duration_seconds, target.max_duration_seconds, time_budget),
                "maximum_turns": min(request.maximum_turns, turn_budget),
                "maximum_concurrency": min(request.maximum_concurrency, target.max_concurrency),
                "maximum_tokens": min(request.maximum_tokens, token_budget),
            },
            "configuration": configuration,
            "callback_url": f"{api_base_url.rstrip('/')}/internal/framework-events",
        }

    def cancel_assessment(self, target_id: str | None = None, assessment_id: str | None = None) -> dict[str, Any]:
        marker = assessment_id or target_id or "global"
        path = self.cancel_dir / f"{marker}.cancel"
        path.write_text(datetime.now(UTC).isoformat(), encoding="utf-8")
        return {"cancel_requested": True, "marker": marker, "path": str(path)}

    def _cancel_requested(self, result: FrameworkAssessmentResult, target_id: str) -> bool:
        return any(
            path.exists()
            for path in (
                self.cancel_dir / "global.cancel",
                self.cancel_dir / f"{target_id}.cancel",
                self.cancel_dir / f"{result.id}.cancel",
            )
        )

    def _clear_cancel_markers(self, target_id: str) -> None:
        for path in (self.cancel_dir / "global.cancel", self.cancel_dir / f"{target_id}.cancel"):
            if path.exists():
                path.unlink()

    def _execute_framework(
        self,
        *,
        request: FrameworkAssessmentRequest,
        result: FrameworkAssessmentResult,
        target: Any,
        framework_id: str,
        api_base_url: str,
        model_roles: dict[str, Any],
        inherited_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        framework = self.frameworks.get(framework_id)
        if not framework:
            result.errors.append(f"Unknown framework: {framework_id}")
            return None
        if not framework.enabled:
            result.errors.append(f"Framework disabled: {framework_id}")
            return None
        payload = self._build_execution_payload(
            request=request,
            result=result,
            target=target,
            framework_id=framework_id,
            api_base_url=api_base_url,
            model_roles=model_roles,
            inherited_context=inherited_context,
        )
        try:
            response = httpx.post(f"{framework.worker_url}/execute", json=payload, timeout=request.maximum_duration_seconds + 30)
            response.raise_for_status()
            data = response.json()
            result.worker_results.append(data)
            result.normalized_evidence.extend(data.get("evidence", []))
            for worker_error in data.get("errors", []):
                result.errors.append(f"{framework_id}: {worker_error}")
            return data
        except Exception as exc:
            result.errors.append(f"{framework_id}: {exc}")
            return None

    def _evidence_signal(self, evidence: list[dict[str, Any]]) -> dict[str, Any]:
        categories = sorted({str(item.get("category") or item.get("vulnerability") or "").lower() for item in evidence if item})
        probes = sorted({str(item.get("probe") or "").lower() for item in evidence if item.get("probe")})
        confirmed = [item for item in evidence if item.get("confirmed") or item.get("success")]
        candidate = [item for item in evidence if item.get("candidate", True)]
        text = " ".join(categories + probes)
        return {
            "categories": categories,
            "probes": probes,
            "confirmed_count": len(confirmed),
            "candidate_count": len(candidate),
            "has_prompt_leakage": "leak" in text or "system_prompt" in text,
            "has_injection": "inject" in text or "jailbreak" in text,
            "has_tool_or_retrieval": "tool" in text or "retrieval" in text or "rag" in text,
        }

    def _next_frameworks(self, completed: list[str], latest: dict[str, Any] | None, requested: list[str]) -> list[dict[str, Any]]:
        evidence = list((latest or {}).get("evidence", []))
        signal = self._evidence_signal(evidence)
        plan: list[dict[str, Any]] = []
        allowed = [item for item in CHAIN_ORDER if item in requested]
        def add(framework: str, reason: str) -> None:
            if framework in allowed and framework not in completed and all(item["framework"] != framework for item in plan):
                plan.append({"framework": framework, "reason": reason, "trigger": signal})
        if not latest:
            add(CHAIN_START if CHAIN_START in allowed else allowed[0], "Initial reconnaissance and broad probe discovery")
            return plan
        if latest.get("framework") == "garak":
            if signal["has_prompt_leakage"] or signal["has_injection"] or signal["candidate_count"]:
                add("pyrit", "Expand garak candidates into targeted PyRIT attack execution")
                add("promptfoo", "Create reproducibility checks for garak-observed weakness")
            else:
                add("promptfoo", "Run deterministic regression assertions when garak has no confirmed signal")
        elif latest.get("framework") == "pyrit":
            add("promptfoo", "Confirm PyRIT-observed behavior with repeatable Promptfoo assertions")
            if signal["has_injection"] or signal["has_tool_or_retrieval"] or signal["candidate_count"]:
                add("deepteam", "Explore related DeepTeam vulnerability paths")
        elif latest.get("framework") == "promptfoo":
            if signal["confirmed_count"] or signal["candidate_count"]:
                add("deepteam", "Explore adjacent attack paths after reproducibility confirmation")
        return plan

    def _correlation_key(self, evidence: dict[str, Any]) -> str:
        vulnerability = str(evidence.get("vulnerability") or evidence.get("category") or "unknown").lower()
        if "leak" in vulnerability or "system_prompt" in str(evidence.get("probe", "")).lower():
            return "prompt-leakage"
        if "inject" in vulnerability or "jailbreak" in vulnerability:
            return "prompt-injection-jailbreak"
        if "retrieval" in vulnerability or "rag" in vulnerability:
            return "retrieval-rag-security"
        if "tool" in vulnerability or "agency" in vulnerability:
            return "tool-authorization-agency"
        if "memory" in vulnerability:
            return "memory-isolation"
        return vulnerability

    def correlate_evidence(self, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for item in evidence:
            groups.setdefault(self._correlation_key(item), []).append(item)
        findings = []
        for index, (key, rows) in enumerate(sorted(groups.items()), start=1):
            frameworks = sorted({str(row.get("framework", "unknown")) for row in rows})
            confirmed_rows = [row for row in rows if row.get("confirmed") or row.get("success")]
            max_confidence = max(float(row.get("confidence", 0) or 0) for row in rows)
            confidence = min(0.99, max_confidence + 0.08 * max(0, len(frameworks) - 1) + 0.03 * len(confirmed_rows))
            status = "confirmed" if confirmed_rows or len(frameworks) >= 2 else "candidate"
            findings.append(
                {
                    "id": f"CORR-{index:03d}-{key}",
                    "title": key.replace("-", " ").title(),
                    "status": status,
                    "confidence": round(confidence, 3),
                    "frameworks": frameworks,
                    "evidence_count": len(rows),
                    "confirmed_evidence_count": len(confirmed_rows),
                    "categories": sorted({str(row.get("category") or "") for row in rows if row.get("category")}),
                    "evidence_ids": [str(row.get("execution_id") or row.get("id") or row.get("evidence_hash")) for row in rows],
                    "native_artifacts": sorted({str(row.get("native_artifact_path")) for row in rows if row.get("native_artifact_path")}),
                    "sample_prompts": [str(row.get("prompt", ""))[:240] for row in rows[:3]],
                    "sample_responses": [str(row.get("response", ""))[:240] for row in rows[:3]],
                    "iso_42001_evidence_mapping": [
                        "A.6 AI system impact and risk assessment",
                        "A.7 AI system data and model controls",
                        "A.8 AI system operation monitoring and incident evidence",
                    ],
                    "owasp_llm_mapping": sorted({str(row.get("category") or row.get("vulnerability") or "") for row in rows}),
                }
            )
        return findings

    def run_chained_assessment(self, request: FrameworkAssessmentRequest, api_base_url: str) -> FrameworkAssessmentResult:
        target = self.target_manager.get_target(request.target_id)
        if not request.written_authorization_confirmed or not target.authorization_confirmed:
            raise ValueError("Written authorization must be confirmed")
        if not target.enabled:
            raise ValueError(f"Target is disabled: {target.disabled_reason}")
        requested = [framework for framework in (request.frameworks or CHAIN_ORDER) if framework in self.frameworks]
        disabled_requested = [framework for framework in requested if not self.frameworks[framework].enabled]
        requested = [framework for framework in requested if self.frameworks[framework].enabled]
        if not requested:
            raise ValueError("No enabled frameworks were selected for this assessment")
        complete_chain = request.strategy in {"complete-pentest", "full-chain", "pentest"}
        self._clear_cancel_markers(target.id)
        result = FrameworkAssessmentResult(target_id=target.id, frameworks=[])
        model_roles = self._model_roles(request, target.model_name)
        if model_roles.get("bias_warning"):
            result.warnings.append(model_roles["bias_warning"])
        if disabled_requested:
            result.warnings.append(f"Disabled frameworks skipped: {', '.join(disabled_requested)}")
        completed: list[str] = []
        latest: dict[str, Any] | None = None
        inherited_context: dict[str, Any] = {}
        step = 0
        while len(completed) < len(requested):
            if self._cancel_requested(result, target.id):
                result.status = "cancelled"
                result.chain_events.append(
                    {
                        "event": "planner_stopped",
                        "reason": "cancel_requested",
                        "rationale": "Assessment cancellation was requested by the operator.",
                        "at": datetime.now(UTC).isoformat(),
                    }
                )
                break
            step += 1
            correlated_findings = self.correlate_evidence(result.normalized_evidence)
            context = self.planner.build_context(
                request=request,
                result=result,
                target=target,
                requested_frameworks=requested,
                correlated_findings=correlated_findings,
                latest=latest,
            )
            if complete_chain:
                remaining = [framework for framework in requested if framework not in completed]
                if remaining:
                    next_framework = remaining[0]
                    decision = PlannerDecision(
                        next_framework=next_framework,
                        action_type="complete_pentest_stage",
                        objective=request.objective,
                        profile=request.profile,
                        request_budget=max(1, min(6, context.remaining_budget.requests or request.maximum_requests)),
                        turn_budget=max(1, min(4, context.remaining_budget.turns or request.maximum_turns)),
                        token_budget=max(1, min(request.maximum_tokens, context.remaining_budget.tokens or request.maximum_tokens)),
                        time_budget_seconds=max(1, min(request.maximum_duration_seconds, context.remaining_budget.time_seconds or request.maximum_duration_seconds)),
                        rationale=(
                            f"Complete assessment mode runs the stable native engines in presentation order. "
                            f"Next stage: {next_framework}."
                        ),
                        evidence_references=[f"target:{target.id}", "mode:complete-pentest"],
                        expected_confirmation_condition="Native framework artifact and normalized evidence are recorded.",
                        continue_assessment=True,
                        policy_rule_id="complete-pentest-fixed-order",
                        safety_decision={"approved": True, "reason": "complete_pentest_mode"},
                    )
                else:
                    decision = PlannerDecision(
                        action_type="stop",
                        objective=request.objective,
                        rationale="All selected stable frameworks completed.",
                        continue_assessment=False,
                        stop_reason="requested_frameworks_completed",
                        policy_rule_id="complete-pentest-complete",
                        safety_decision={"approved": True, "reason": "requested_frameworks_completed"},
                    )
            else:
                decision = self.planner.decide(context, request, model_roles)
            self.planner.persist(result.id, step, context, decision)
            decision_row = decision.model_dump(mode="json")
            result.execution_plan.append(decision_row)
            if not decision.continue_assessment or not decision.next_framework:
                result.chain_events.append(
                    {
                        "event": "planner_stopped",
                        "reason": decision.stop_reason,
                        "rationale": decision.rationale,
                        "at": datetime.now(UTC).isoformat(),
                    }
                )
                break
            framework_id = decision.next_framework
            result.chain_events.append(
                {
                    "event": "framework_selected",
                    "framework": framework_id,
                    "reason": decision.rationale,
                    "policy_rule_id": decision.policy_rule_id,
                    "evidence_references": decision.evidence_references,
                    "expected_confirmation_condition": decision.expected_confirmation_condition,
                    "at": datetime.now(UTC).isoformat(),
                }
            )
            inherited_context = {
                "completed_frameworks": completed,
                "correlated_findings": correlated_findings,
                "planner_context_artifact": f"data/planner-artifacts/{result.id}/step-{step:02d}-context.json",
                "planner_decision_artifact": f"data/planner-artifacts/{result.id}/step-{step:02d}-decision.json",
                "planner_decision": decision_row,
            }
            latest = self._execute_framework(
                request=request,
                result=result,
                target=target,
                framework_id=framework_id,
                api_base_url=api_base_url,
                model_roles=model_roles,
                inherited_context=inherited_context,
            )
            completed.append(framework_id)
            result.frameworks.append(framework_id)
            self._save_result(result)
            if self._cancel_requested(result, target.id):
                result.status = "cancelled"
                result.chain_events.append(
                    {
                        "event": "planner_stopped",
                        "reason": "cancel_requested",
                        "rationale": "Assessment cancellation was requested after the current framework stage completed.",
                        "at": datetime.now(UTC).isoformat(),
                    }
                )
                break
            inherited_context = {
                "completed_frameworks": completed,
                "correlated_findings": self.correlate_evidence(result.normalized_evidence),
                "latest_signal": self._evidence_signal(list((latest or {}).get("evidence", []))),
                "planner_decision": decision_row,
            }
        result.correlated_findings = self.correlate_evidence(result.normalized_evidence)
        result.completed_at = datetime.now(UTC)
        if result.status != "cancelled":
            result.status = "succeeded" if result.normalized_evidence and not result.errors else "partially_completed" if result.normalized_evidence else "failed"
        self._save_result(result)
        return result

    def run_assessment(self, request: FrameworkAssessmentRequest, api_base_url: str) -> FrameworkAssessmentResult:
        if request.execution_mode == "chained" or request.strategy in {"chained", "adaptive", "attack-planning"}:
            return self.run_chained_assessment(request, api_base_url)
        target = self.target_manager.get_target(request.target_id)
        if not request.written_authorization_confirmed or not target.authorization_confirmed:
            raise ValueError("Written authorization must be confirmed")
        if not target.enabled:
            raise ValueError(f"Target is disabled: {target.disabled_reason}")
        self._clear_cancel_markers(target.id)

        requested = [framework for framework in request.frameworks if framework in self.frameworks]
        disabled_requested = [framework for framework in requested if not self.frameworks[framework].enabled]
        requested = [framework for framework in requested if self.frameworks[framework].enabled]
        if not requested:
            raise ValueError("No enabled frameworks were selected for this assessment")

        result = FrameworkAssessmentResult(target_id=target.id, frameworks=requested)
        model_roles = self._model_roles(request, target.model_name)
        if model_roles.get("bias_warning"):
            result.warnings.append(model_roles["bias_warning"])
        if disabled_requested:
            result.warnings.append(f"Disabled frameworks skipped: {', '.join(disabled_requested)}")
        for framework_id in requested:
            self._execute_framework(
                request=request,
                result=result,
                target=target,
                framework_id=framework_id,
                api_base_url=api_base_url,
                model_roles=model_roles,
            )

        result.completed_at = datetime.now(UTC)
        result.correlated_findings = self.correlate_evidence(result.normalized_evidence)
        result.status = "succeeded" if result.normalized_evidence and not result.errors else "partially_completed" if result.normalized_evidence else "failed"
        self._save_result(result)
        return result

    def _save_result(self, result: FrameworkAssessmentResult) -> None:
        result.reports = write_framework_reports(result, self.root / "data" / "reports")
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
                    "findings": len(data.correlated_findings),
                    "confirmed": sum(1 for item in data.correlated_findings if item.get("status") == "confirmed"),
                    "candidates": sum(1 for item in data.correlated_findings if item.get("status") != "confirmed"),
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
