import pytest

from packages.security_assurance.framework_models import FrameworkAssessmentRequest


@pytest.mark.parametrize("attack", ["prompt_sending", "red_teaming", "crescendo", "tap"])
def test_api_accepts_allowlisted_pyrit_attack(attack):
    request = FrameworkAssessmentRequest(target_id="T", pyrit_attack=attack)
    assert request.pyrit_attack == attack


def test_api_rejects_unknown_pyrit_attack():
    with pytest.raises(ValueError):
        FrameworkAssessmentRequest(target_id="T", pyrit_attack="unknown")
