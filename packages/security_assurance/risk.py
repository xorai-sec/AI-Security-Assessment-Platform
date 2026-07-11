from __future__ import annotations

from .models import Severity


def score_to_severity(score: float) -> Severity:
    if score >= 8.5:
        return Severity.critical
    if score >= 6.5:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0:
        return Severity.low
    return Severity.info


def calculate_risk(
    likelihood: float,
    technical_impact: float,
    business_impact: float,
    reproducibility: float,
    detectability: float,
) -> dict[str, float | str]:
    score = (
        likelihood * 0.22
        + technical_impact * 0.25
        + business_impact * 0.25
        + reproducibility * 0.18
        + (10 - detectability) * 0.10
    )
    severity = score_to_severity(score)
    return {
        "score": round(score, 2),
        "severity": severity.value,
        "formula": "0.22L + 0.25T + 0.25B + 0.18R + 0.10(10-D)",
    }

