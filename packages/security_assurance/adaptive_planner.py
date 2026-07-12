from __future__ import annotations

import json
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import BaseModel, Field

from .framework_models import FrameworkAssessmentRequest, FrameworkAssessmentResult, FrameworkDefinition


class PlanningBudget(BaseModel):
    requests: int
    turns: int
    tokens: int
    time_seconds: int


class PlanningContext(BaseModel):
    assessment_id: str
    policy_version: str
    target_id: str
    target_type: str
    target_visibility: str
    target_capabilities: dict[str, bool]
    assessment_objective: str
    requested_frameworks: list[str]
    completed_framework_stages: list[str]
    evidence_categories: list[str]
    confidence_scores: list[float]
    detector_results: list[dict[str, Any]]
    scorer_results: list[dict[str, Any]]
    assertion_results: list[dict[str, Any]]
    correlated_finding_candidates: list[dict[str, Any]]
    remaining_budget: PlanningBudget
    prior_errors: list[str]
    unsupported_capabilities: list[str]
    framework_failures: dict[str, int]
    duplicate_evidence_count: int
    authorization_confirmed: bool
    target_enabled: bool
    kill_switch_active: bool = False
    latest_framework: str | None = None
    latest_evidence_count: int = 0


class PlannerDecision(BaseModel):
    next_framework: str | None = None
    action_type: str = "stop"
    objective: str = ""
    selected_plugins: list[str] = Field(default_factory=list)
    selected_probes: list[str] = Field(default_factory=list)
    selected_converters: list[str] = Field(default_factory=list)
    selected_vulnerabilities: list[str] = Field(default_factory=list)
    selected_attacks: list[str] = Field(default_factory=list)
    selected_strategies: list[str] = Field(default_factory=list)
    profile: str = "quick"
    request_budget: int = 0
    turn_budget: int = 0
    token_budget: int = 0
    time_budget_seconds: int = 0
    rationale: str = ""
    evidence_references: list[str] = Field(default_factory=list)
    expected_confirmation_condition: str = ""
    continue_assessment: bool = False
    stop_reason: str | None = None
    policy_rule_id: str | None = None
    native_engine_required: bool = True
    llm_recommendation: dict[str, Any] | None = None
    safety_decision: dict[str, Any] = Field(default_factory=dict)


class AdaptiveAttackPlanner:
    def __init__(self, root: Path, frameworks: dict[str, FrameworkDefinition]) -> None:
        self.root = root
        self.frameworks = frameworks
        default_policy = root / "data" / "planner-policies" / "adaptive-planner-v1.yaml"
        self.policy_path = Path(os.getenv("ADAPTIVE_PLANNER_POLICY", default_policy))
        self.artifact_root = root / "data" / "planner-artifacts"
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.policy = self._load_policy()

    def _load_policy(self) -> dict[str, Any]:
        data = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data.get("version"):
            raise ValueError(f"Invalid adaptive planner policy: {self.policy_path}")
        return data

    def build_context(
        self,
        *,
        request: FrameworkAssessmentRequest,
        result: FrameworkAssessmentResult,
        target: Any,
        requested_frameworks: list[str],
        correlated_findings: list[dict[str, Any]],
        latest: dict[str, Any] | None,
    ) -> PlanningContext:
        target_capabilities = self._target_capabilities(target)
        evidence = result.normalized_evidence
        latest_evidence = list((latest or {}).get("evidence", []))
        confidence_scores = [float(item.get("confidence", 0) or 0) for item in evidence if isinstance(item, dict)]
        categories = sorted(
            {
                str(item.get("category") or item.get("vulnerability") or item.get("probe") or "").lower()
                for item in evidence
                if isinstance(item, dict) and (item.get("category") or item.get("vulnerability") or item.get("probe"))
            }
        )
        signatures = [
            "|".join(
                [
                    str(item.get("framework", "")),
                    str(item.get("category") or item.get("vulnerability") or ""),
                    str(item.get("prompt") or "")[:120],
                    str(item.get("response") or "")[:120],
                ]
            )
            for item in evidence
            if isinstance(item, dict)
        ]
        duplicate_count = max(Counter(signatures).values(), default=0)
        framework_failures = self._framework_failures(result.errors)
        unsupported = [
            error for error in result.errors if "unsupported" in error.lower() or "not supported" in error.lower()
        ]
        requests_used = max(len(evidence), len(result.worker_results))
        elapsed = 0
        if result.started_at:
            elapsed = max(0, int((datetime.now(UTC) - result.started_at).total_seconds()))
        return PlanningContext(
            assessment_id=result.id,
            policy_version=str(self.policy["version"]),
            target_id=target.id,
            target_type=str(getattr(target.target_type, "value", target.target_type)),
            target_visibility=str(getattr(target.visibility, "value", target.visibility)),
            target_capabilities=target_capabilities,
            assessment_objective=request.objective,
            requested_frameworks=requested_frameworks,
            completed_framework_stages=list(result.frameworks),
            evidence_categories=categories,
            confidence_scores=confidence_scores,
            detector_results=self._collect_named_results(evidence, ("detector", "detector_result", "detectors")),
            scorer_results=self._collect_named_results(evidence, ("scorer", "score", "score_result", "scorer_result")),
            assertion_results=self._collect_named_results(evidence, ("assertion", "assertions", "assertion_result")),
            correlated_finding_candidates=correlated_findings,
            remaining_budget=PlanningBudget(
                requests=max(
                    0,
                    min(request.maximum_requests, getattr(target, "max_requests", request.maximum_requests))
                    - requests_used,
                ),
                turns=max(0, request.maximum_turns - len(result.frameworks)),
                tokens=max(0, request.maximum_tokens),
                time_seconds=max(
                    0,
                    min(
                        request.maximum_duration_seconds,
                        getattr(target, "max_duration_seconds", request.maximum_duration_seconds),
                    )
                    - elapsed,
                ),
            ),
            prior_errors=list(result.errors),
            unsupported_capabilities=unsupported,
            framework_failures=framework_failures,
            duplicate_evidence_count=duplicate_count,
            authorization_confirmed=bool(
                request.written_authorization_confirmed and getattr(target, "authorization_confirmed", False)
            ),
            target_enabled=bool(getattr(target, "enabled", False)),
            kill_switch_active=os.getenv("ADAPTIVE_PLANNER_KILL_SWITCH", "false").lower() == "true",
            latest_framework=str((latest or {}).get("framework")) if latest else None,
            latest_evidence_count=len(latest_evidence),
        )

    def decide(
        self,
        context: PlanningContext,
        request: FrameworkAssessmentRequest,
        model_roles: dict[str, Any],
    ) -> PlannerDecision:
        stop = self._termination_decision(context)
        if stop:
            return stop
        llm_recommendation = self._llm_recommendation(context, model_roles) if self._llm_enabled() else None
        rules = sorted(self.policy.get("rules", []), key=lambda item: int(item.get("priority", 0)), reverse=True)
        for rule in rules:
            if not self._matches(rule.get("when", {}), context):
                continue
            decision = self._decision_from_rule(rule, context, llm_recommendation)
            decision = self._validate_and_filter(decision, context)
            if decision.continue_assessment:
                return decision
        return self._stop(
            context,
            "no_useful_next_action",
            "No policy rule matched the current evidence, capability, and budget state.",
            llm_recommendation=llm_recommendation,
        )

    def persist(self, assessment_id: str, step: int, context: PlanningContext, decision: PlannerDecision) -> None:
        directory = self.artifact_root / assessment_id
        directory.mkdir(parents=True, exist_ok=True)
        prefix = f"step-{step:02d}"
        (directory / f"{prefix}-context.json").write_text(context.model_dump_json(indent=2), encoding="utf-8")
        (directory / f"{prefix}-decision.json").write_text(decision.model_dump_json(indent=2), encoding="utf-8")
        (directory / "policy-version.txt").write_text(
            f"{context.policy_version}\n{self.policy_path}\n",
            encoding="utf-8",
        )

    def _target_capabilities(self, target: Any) -> dict[str, bool]:
        declared = getattr(target, "declared_capabilities", None)
        discovered = getattr(target, "discovered_capabilities", None)
        values: dict[str, bool] = {}
        for source in (declared, discovered):
            if source is None:
                continue
            for key, value in source.model_dump().items():
                values[key] = bool(values.get(key, False) or value)
        target_type = str(getattr(getattr(target, "target_type", ""), "value", getattr(target, "target_type", "")))
        if target_type == "ollama":
            values.update({"local_model": True, "chat": True, "rag": False, "tools": False, "memory": False})
        if target_type in {"enterprise_assist", "generic_rag"}:
            values["rag"] = True
        if target_type in {"enterprise_assist", "generic_agent"}:
            values["tools"] = bool(values.get("tools", True))
            values["memory"] = bool(values.get("memory", True))
        visibility = str(getattr(getattr(target, "visibility", ""), "value", getattr(target, "visibility", "")))
        values["white_box"] = visibility == "white_box"
        values["grey_box"] = visibility == "grey_box"
        values["black_box"] = visibility == "black_box"
        return values

    def _framework_failures(self, errors: list[str]) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for error in errors:
            prefix = error.split(":", 1)[0].strip().lower()
            if prefix:
                counts[prefix] += 1
        return dict(counts)

    def _collect_named_results(self, evidence: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            for key in keys:
                if key in item and item[key] not in (None, "", []):
                    rows.append(
                        {
                            "framework": item.get("framework"),
                            "key": key,
                            "value": item[key],
                            "evidence_id": self._evidence_id(item),
                            "category": item.get("category") or item.get("vulnerability"),
                        }
                    )
        return rows[:100]

    def _termination_decision(self, context: PlanningContext) -> PlannerDecision | None:
        termination = self.policy.get("termination", {})
        if context.kill_switch_active:
            return self._stop(context, "kill_switch_active", "Adaptive planner kill switch is enabled.")
        if not context.authorization_confirmed:
            return self._stop(context, "authorization_missing", "Written authorization is not confirmed.")
        if not context.target_enabled:
            return self._stop(context, "target_disabled", "Target is disabled.")
        if context.remaining_budget.requests < int(termination.get("minimum_remaining_requests", 1)):
            return self._stop(context, "budget_exhausted", "Remaining request budget is exhausted.")
        if context.remaining_budget.time_seconds <= 0 or context.remaining_budget.turns <= 0:
            return self._stop(context, "budget_exhausted", "Remaining time or turn budget is exhausted.")
        if context.duplicate_evidence_count >= int(termination.get("duplicate_evidence_threshold", 3)):
            return self._stop(
                context,
                "repeated_duplicate_evidence",
                "Recent evidence is repeating without new signal.",
            )
        failure_threshold = int(termination.get("maximum_framework_failures", 2))
        failing = [framework for framework, count in context.framework_failures.items() if count >= failure_threshold]
        if failing:
            return self._stop(
                context,
                "framework_failure_threshold",
                f"Framework failure threshold reached for {', '.join(sorted(failing))}.",
            )
        confirmed_threshold = float(termination.get("confirmed_confidence_threshold", 0.88))
        confirmed = [
            finding
            for finding in context.correlated_finding_candidates
            if finding.get("status") == "confirmed" and float(finding.get("confidence", 0) or 0) >= confirmed_threshold
        ]
        if confirmed and "comprehensive" != os.getenv("PROFILE", "").lower() and context.completed_framework_stages:
            return self._stop(
                context,
                "objective_confirmed",
                "Objective has confirmed correlated evidence at the configured confidence threshold.",
            )
        if set(context.requested_frameworks).issubset(set(context.completed_framework_stages)):
            return self._stop(context, "requested_frameworks_completed", "All requested frameworks have completed.")
        return None

    def _stop(
        self,
        context: PlanningContext,
        reason: str,
        rationale: str,
        llm_recommendation: dict[str, Any] | None = None,
    ) -> PlannerDecision:
        return PlannerDecision(
            action_type="stop",
            objective=context.assessment_objective,
            rationale=rationale,
            evidence_references=self._evidence_references(context),
            continue_assessment=False,
            stop_reason=reason,
            policy_rule_id="termination",
            llm_recommendation=llm_recommendation,
            safety_decision={"approved": True, "reason": reason},
        )

    def _matches(self, expression: Any, context: PlanningContext) -> bool:
        if expression in ({}, None):
            return True
        if isinstance(expression, list):
            return all(self._matches(item, context) for item in expression)
        if not isinstance(expression, dict):
            return bool(expression)
        if "all" in expression:
            return all(self._matches(item, context) for item in expression["all"])
        if "any" in expression:
            return any(self._matches(item, context) for item in expression["any"])
        if "not" in expression:
            return not self._matches(expression["not"], context)
        for key, value in expression.items():
            if key == "completed_count_equals" and len(context.completed_framework_stages) != int(value):
                return False
            if key == "completed_contains" and str(value) not in context.completed_framework_stages:
                return False
            if key == "completed_not_contains" and str(value) in context.completed_framework_stages:
                return False
            if key == "requested_contains" and str(value) not in context.requested_frameworks:
                return False
            if key == "target_type_in" and context.target_type not in set(map(str, value)):
                return False
            if key == "target_capability" and not context.target_capabilities.get(str(value), False):
                return False
            if key == "evidence_category_contains" and not any(
                str(value).lower() in category for category in context.evidence_categories
            ):
                return False
            if key == "confidence_at_least" and max(context.confidence_scores or [0]) < float(value):
                return False
            if key == "correlated_status_in":
                allowed = set(map(str, value))
                if not any(str(item.get("status")) in allowed for item in context.correlated_finding_candidates):
                    return False
            if key == "assertion_result_contains":
                needle = str(value).lower()
                if not any(needle in json.dumps(item, default=str).lower() for item in context.assertion_results):
                    return False
            if key == "detector_result_contains":
                needle = str(value).lower()
                if not any(needle in json.dumps(item, default=str).lower() for item in context.detector_results):
                    return False
            if (
                key == "evidence_count_at_least"
                and len(context.evidence_categories) < int(value)
                and not context.confidence_scores
            ):
                return False
            if key == "evidence_count_less_than" and (
                len(context.evidence_categories) >= int(value) or bool(context.confidence_scores)
            ):
                return False
        return True

    def _decision_from_rule(
        self,
        rule: dict[str, Any],
        context: PlanningContext,
        llm_recommendation: dict[str, Any] | None,
    ) -> PlannerDecision:
        defaults = self.policy.get("defaults", {})
        raw = dict(rule.get("decision", {}))
        return PlannerDecision(
            next_framework=raw.get("next_framework"),
            action_type=raw.get("action_type", "execute"),
            objective=raw.get("objective", context.assessment_objective),
            selected_plugins=list(raw.get("selected_plugins", [])),
            selected_probes=list(raw.get("selected_probes", [])),
            selected_converters=list(raw.get("selected_converters", [])),
            selected_vulnerabilities=list(raw.get("selected_vulnerabilities", [])),
            selected_attacks=list(raw.get("selected_attacks", [])),
            selected_strategies=list(raw.get("selected_strategies", [])),
            profile=str(raw.get("profile", defaults.get("profile", "quick"))),
            request_budget=int(raw.get("request_budget", defaults.get("request_budget", 4))),
            turn_budget=int(raw.get("turn_budget", defaults.get("turn_budget", 3))),
            token_budget=int(raw.get("token_budget", defaults.get("token_budget", 2048))),
            time_budget_seconds=int(raw.get("time_budget_seconds", defaults.get("time_budget_seconds", 900))),
            rationale=str(raw.get("rationale", "")),
            evidence_references=self._evidence_references(context, rule_id=rule.get("id")),
            expected_confirmation_condition=str(raw.get("expected_confirmation_condition", "")),
            continue_assessment=True,
            policy_rule_id=str(rule.get("id")),
            llm_recommendation=llm_recommendation,
        )

    def _validate_and_filter(self, decision: PlannerDecision, context: PlanningContext) -> PlannerDecision:
        safety_notes: list[str] = []
        if not decision.next_framework:
            decision.continue_assessment = False
            decision.stop_reason = "no_framework_selected"
            decision.safety_decision = {"approved": False, "notes": ["No framework selected."]}
            return decision
        if decision.next_framework not in context.requested_frameworks:
            decision.continue_assessment = False
            decision.stop_reason = "framework_not_requested"
            decision.safety_decision = {"approved": False, "notes": [f"{decision.next_framework} was not requested."]}
            return decision
        if decision.next_framework in context.completed_framework_stages:
            decision.continue_assessment = False
            decision.stop_reason = "framework_already_completed"
            decision.safety_decision = {"approved": False, "notes": [f"{decision.next_framework} already completed."]}
            return decision
        framework = self.frameworks.get(decision.next_framework)
        if not framework or not framework.enabled:
            decision.continue_assessment = False
            decision.stop_reason = "framework_unavailable"
            decision.safety_decision = {
                "approved": False,
                "notes": [f"{decision.next_framework} is unavailable or disabled."],
            }
            return decision
        decision.request_budget = max(1, min(decision.request_budget, context.remaining_budget.requests))
        decision.turn_budget = max(1, min(decision.turn_budget, context.remaining_budget.turns))
        decision.token_budget = max(1, min(decision.token_budget, context.remaining_budget.tokens))
        decision.time_budget_seconds = max(1, min(decision.time_budget_seconds, context.remaining_budget.time_seconds))
        self._filter_framework_plugins(decision, safety_notes)
        self._filter_by_target_capabilities(decision, context, safety_notes)
        if not self._has_required_selection(decision):
            decision.continue_assessment = False
            decision.stop_reason = "no_supported_plugin_after_filtering"
            safety_notes.append(
                "All selected probes/plugins/vulnerabilities were removed by allowlist or capability filtering."
            )
        decision.safety_decision = {"approved": decision.continue_assessment, "notes": safety_notes}
        return decision

    def _filter_framework_plugins(self, decision: PlannerDecision, safety_notes: list[str]) -> None:
        allowlist = self.policy.get("framework_plugin_allowlist", {}).get(decision.next_framework or "", {})
        mappings = {
            "selected_probes": "probes",
            "selected_plugins": "plugins",
            "selected_converters": "converters",
            "selected_vulnerabilities": "vulnerabilities",
            "selected_attacks": "attacks",
            "selected_strategies": "strategies",
        }
        for field_name, allowlist_key in mappings.items():
            selected = getattr(decision, field_name)
            if not selected:
                continue
            allowed = set(map(str, allowlist.get(allowlist_key, [])))
            if not allowed:
                continue
            filtered = [item for item in selected if item in allowed]
            removed = sorted(set(selected) - set(filtered))
            if removed:
                safety_notes.append(f"Removed unsupported {allowlist_key}: {', '.join(removed)}")
            setattr(decision, field_name, filtered)

    def _filter_by_target_capabilities(
        self,
        decision: PlannerDecision,
        context: PlanningContext,
        safety_notes: list[str],
    ) -> None:
        filters = self.policy.get("capability_filters", {})
        fields = [
            "selected_probes",
            "selected_plugins",
            "selected_converters",
            "selected_vulnerabilities",
            "selected_attacks",
            "selected_strategies",
        ]
        for capability, rule in filters.items():
            if context.target_capabilities.get(capability, False):
                continue
            terms = [str(term).lower() for term in rule.get("remove_terms", [])]
            for field_name in fields:
                selected = getattr(decision, field_name)
                filtered = [item for item in selected if not any(term in item.lower() for term in terms)]
                removed = sorted(set(selected) - set(filtered))
                if removed:
                    safety_notes.append(
                        f"Removed {capability}-dependent selections from {field_name}: {', '.join(removed)}"
                    )
                setattr(decision, field_name, filtered)

    def _has_required_selection(self, decision: PlannerDecision) -> bool:
        if decision.next_framework == "garak":
            return bool(decision.selected_probes)
        if decision.next_framework == "pyrit":
            return bool(decision.selected_converters) or decision.action_type == "multi_turn_exploitation"
        if decision.next_framework == "promptfoo":
            return bool(decision.selected_plugins or decision.selected_strategies)
        if decision.next_framework == "deepteam":
            return bool(decision.selected_vulnerabilities)
        return True

    def _evidence_references(self, context: PlanningContext, rule_id: str | None = None) -> list[str]:
        refs: list[str] = [f"target:{context.target_id}"]
        if rule_id:
            refs.append(f"policy:{rule_id}")
        for finding in context.correlated_finding_candidates[:5]:
            refs.append(str(finding.get("id") or finding.get("title") or "correlated-finding"))
            for evidence_id in finding.get("evidence_ids", [])[:3]:
                refs.append(str(evidence_id))
        for row in context.detector_results[:3] + context.scorer_results[:3] + context.assertion_results[:3]:
            refs.append(str(row.get("evidence_id") or row.get("key")))
        return list(dict.fromkeys(refs))

    def _evidence_id(self, item: dict[str, Any]) -> str:
        return str(
            item.get("evidence_id")
            or item.get("execution_id")
            or item.get("id")
            or item.get("evidence_hash")
            or item.get("framework")
            or "evidence"
        )

    def _llm_enabled(self) -> bool:
        return os.getenv("ADAPTIVE_PLANNER_LLM_ENABLED", "false").lower() == "true"

    def _llm_recommendation(self, context: PlanningContext, model_roles: dict[str, Any]) -> dict[str, Any] | None:
        model = os.getenv("OLLAMA_PLANNER_MODEL") or model_roles.get("attacker_model")
        if not model:
            return None
        base_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434").rstrip("/")
        prompt = (
            "Return only JSON with keys next_framework, action_type, objective, rationale, selected_plugins, "
            "selected_probes, selected_converters, selected_vulnerabilities, request_budget, turn_budget. "
            "The deterministic policy will reject unsafe decisions.\n"
            f"Planning context:\n{context.model_dump_json()}"
        )
        try:
            response = httpx.post(
                f"{base_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
                timeout=60,
            )
            response.raise_for_status()
            raw = response.json().get("response", "{}")
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception as exc:
            return {"error": str(exc), "model": model}
        return None
