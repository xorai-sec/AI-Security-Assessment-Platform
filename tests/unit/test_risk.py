from packages.security_assurance.risk import calculate_risk


def test_risk_formula_returns_high_for_repeatable_control_failure() -> None:
    result = calculate_risk(8, 8, 7, 9, 4)
    assert result["score"] >= 6.5
    assert result["severity"] in {"High", "Critical"}

