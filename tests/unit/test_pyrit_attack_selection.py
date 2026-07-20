import pytest
from pathlib import Path

from packages.security_assurance.framework_models import FrameworkAssessmentRequest
from packages.security_assurance.adaptive_planner import PlannerDecision


@pytest.mark.parametrize("attack", ["prompt_sending", "red_teaming", "crescendo", "tap"])
def test_api_accepts_allowlisted_pyrit_attack(attack):
    request = FrameworkAssessmentRequest(target_id="T", pyrit_attack=attack)
    assert request.pyrit_attack == attack


@pytest.mark.parametrize("attack", ["unknown"])
def test_api_rejects_unsupported_pyrit_attack(attack):
    with pytest.raises(ValueError):
        FrameworkAssessmentRequest(target_id="T", pyrit_attack=attack)


def test_complete_stage_decision_carries_explicit_escalated_attack():
    decision = PlannerDecision(
        next_framework="pyrit",
        action_type="complete_pentest_stage",
        pyrit_attack="red_teaming",
        rationale="Prior PyRIT prompts were resisted; escalate to adversarial red teaming.",
    )
    assert decision.pyrit_attack == "red_teaming"
    assert "resisted" in decision.rationale


def test_orchestrated_pyrit_stage_has_no_silent_default():
    source = Path("workers/pyrit-worker/app.py").read_text(encoding="utf-8")
    assert "PyRIT attack strategy must be explicitly selected for orchestrated stages" in source
