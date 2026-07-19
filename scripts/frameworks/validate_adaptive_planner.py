from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from packages.security_assurance.adaptive_planner import AdaptiveAttackPlanner
from packages.security_assurance.framework_models import (
    FrameworkAssessmentRequest,
    FrameworkAssessmentResult,
    FrameworkDefinition,
)
from packages.security_assurance.target_models import TargetCapabilities


def frameworks() -> dict[str, FrameworkDefinition]:
    return {
        name: FrameworkDefinition(id=name, name=name, worker_url=f"http://{name}-worker:8090", enabled=True)
        for name in ("native", "garak", "pyrit", "promptfoo")
    }


def target(
    target_id: str,
    target_type: str,
    *,
    rag: bool = False,
    tools: bool = False,
    memory: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=target_id,
        target_type=target_type,
        visibility="black_box",
        model_name="llama3.2:3b",
        declared_capabilities=TargetCapabilities(
            chat=True,
            multi_turn=True,
            rag=rag,
            tools=tools,
            memory=memory,
            local_model=target_type == "ollama",
            deterministic_test_canaries=target_type == "enterprise_assist",
        ),
        discovered_capabilities=None,
        authorization_confirmed=True,
        enabled=True,
        disabled_reason=None,
        max_requests=20,
        max_duration_seconds=1200,
        max_concurrency=1,
    )


def request(target_id: str) -> FrameworkAssessmentRequest:
    return FrameworkAssessmentRequest(
        target_id=target_id,
        frameworks=["garak", "pyrit", "promptfoo", "native"],
        execution_mode="chained",
        strategy="adaptive",
        objective="Authorized adaptive AI security assessment",
        maximum_requests=12,
        maximum_turns=6,
        maximum_duration_seconds=1200,
        written_authorization_confirmed=True,
    )


def context_and_decision(
    planner: AdaptiveAttackPlanner,
    req: FrameworkAssessmentRequest,
    result: FrameworkAssessmentResult,
    tgt: SimpleNamespace,
    findings: list[dict],
):
    latest = None
    if result.frameworks:
        latest = {"framework": result.frameworks[-1], "evidence": result.normalized_evidence[-1:]}
    context = planner.build_context(
        request=req,
        result=result,
        target=tgt,
        requested_frameworks=req.frameworks,
        correlated_findings=findings,
        latest=latest,
    )
    decision = planner.decide(
        context,
        req,
        {"attacker_model": "llama3.1:8b", "judge_model": "qwen2.5:7b", "target_model": "llama3.2:3b"},
    )
    planner.persist(result.id, len(result.execution_plan) + 1, context, decision)
    return context, decision


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"adaptive-planner-failed: {message}")


def main() -> None:
    planner = AdaptiveAttackPlanner(ROOT, frameworks())

    raw = target("TGT-RAW-OLLAMA", "ollama")
    enterprise = target("TGT-ENTERPRISE", "enterprise_assist", rag=True, tools=True, memory=True)

    raw_initial = FrameworkAssessmentResult(target_id=raw.id, frameworks=[])
    _, raw_initial_decision = context_and_decision(planner, request(raw.id), raw_initial, raw, [])

    enterprise_initial = FrameworkAssessmentResult(target_id=enterprise.id, frameworks=[])
    _, enterprise_initial_decision = context_and_decision(
        planner,
        request(enterprise.id),
        enterprise_initial,
        enterprise,
        [],
    )

    leakage_result = FrameworkAssessmentResult(target_id=raw.id, frameworks=["garak"])
    leakage_result.normalized_evidence = [
        {
            "id": "EV-LEAK-001",
            "framework": "garak",
            "category": "prompt_leakage",
            "probe": "promptinject",
            "detector_result": "fail",
            "confidence": 0.64,
            "prompt": "authorized test prompt",
            "response": "candidate leaked instruction",
        }
    ]
    leakage_findings = [
        {
            "id": "CORR-001-prompt-leakage",
            "status": "candidate",
            "confidence": 0.64,
            "evidence_ids": ["EV-LEAK-001"],
        }
    ]
    _, leakage_decision = context_and_decision(planner, request(raw.id), leakage_result, raw, leakage_findings)

    no_signal_result = FrameworkAssessmentResult(target_id=raw.id, frameworks=["garak"])
    _, no_signal_decision = context_and_decision(planner, request(raw.id), no_signal_result, raw, [])

    assert_true(raw_initial_decision.next_framework == "garak", "raw Ollama initial plan should start with garak")
    assert_true(
        enterprise_initial_decision.next_framework == "garak",
        "enterprise initial plan should start with garak",
    )
    assert_true(
        raw_initial_decision.selected_probes != enterprise_initial_decision.selected_probes,
        "raw Ollama and EnterpriseAssist initial plans must differ",
    )
    assert_true(leakage_decision.next_framework == "pyrit", "leakage evidence should route to PyRIT")
    assert_true(
        no_signal_decision.next_framework == "native",
        "no-signal evidence should not route to the fixed PyRIT path",
    )
    assert_true(
        leakage_decision.next_framework != no_signal_decision.next_framework,
        "different evidence patterns must produce different next frameworks",
    )
    assert_true(
        "CORR-001-prompt-leakage" in leakage_decision.evidence_references,
        "decision must reference correlated evidence",
    )
    assert_true(leakage_decision.request_budget <= 12, "request budget must be bounded")
    assert_true(leakage_decision.continue_assessment, "valid leakage decision should continue")

    print("adaptive-planner-ok")
    print(f"policy={planner.policy['version']}")
    print(f"raw_initial={raw_initial_decision.next_framework}:{','.join(raw_initial_decision.selected_probes)}")
    print(
        f"enterprise_initial={enterprise_initial_decision.next_framework}:"
        f"{','.join(enterprise_initial_decision.selected_probes)}"
    )
    print(
        f"leakage_pattern_next={leakage_decision.next_framework} "
        f"rule={leakage_decision.policy_rule_id} refs={','.join(leakage_decision.evidence_references)}"
    )
    print(f"no_signal_pattern_next={no_signal_decision.next_framework} rule={no_signal_decision.policy_rule_id}")
    print("stable_frameworks=garak,pyrit,promptfoo,native")
    print("artifacts=data/planner-artifacts/<assessment-id>/step-XX-context.json,step-XX-decision.json")


if __name__ == "__main__":
    main()
