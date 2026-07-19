import shutil
from pathlib import Path

from packages.security_assurance.framework_manager import FrameworkManager


def manager(tmp_path):
    policy = tmp_path / "data/planner-policies"
    policy.mkdir(parents=True, exist_ok=True)
    shutil.copy(Path("data/planner-policies/adaptive-planner-v1.yaml"), policy / "adaptive-planner-v1.yaml")
    return FrameworkManager(tmp_path, target_manager=type("T", (), {})())


def row(**values):
    base = {
        "execution_id": "n-1",
        "framework": "native",
        "target_type": "enterprise_assist",
        "category": "prompt_leakage",
        "vulnerability": "sensitive_information_disclosure",
        "prompt": "leak",
        "response": "",
        "confidence": 0.9,
        "success": True,
        "evaluator_results": [{"canary_matched": True}],
        "assessment_canary": "CANARY",
    }
    base.update(values)
    return base


def test_prompt_leakage_native_canary_confirmed(tmp_path):
    findings = manager(tmp_path).correlate_evidence([row(response="CANARY")])
    assert findings[0]["status"] == "confirmed"


def test_telemetry_categories_confirmed(tmp_path):
    for category, field in [
        ("rag_security", "retrieval_trace"),
        ("unauthorized_tool_execution", "tool_trace"),
        ("confirmation_bypass", "authorization_trace"),
        ("memory_isolation", "memory_trace"),
    ]:
        findings = manager(tmp_path).correlate_evidence(
            [row(category=category, vulnerability=category, **{field: [{"executed": True}]})]
        )
        assert findings[0]["status"] == "confirmed"


def test_judge_positive_without_native_telemetry_is_not_confirmed(tmp_path):
    findings = manager(tmp_path).correlate_evidence(
        [row(framework="promptfoo", response="unsafe", evaluator_results=[{"confirmed": True}])]
    )
    assert findings[0]["status"] != "confirmed"


def test_finding_lineage_and_risk_inputs(tmp_path):
    finding = manager(tmp_path).correlate_evidence([row(source_evidence_ids=["g-1", "p-1"])])[0]
    assert finding["lineage_complete"]
    assert "native_confirmation" in finding["risk_score_inputs"]
