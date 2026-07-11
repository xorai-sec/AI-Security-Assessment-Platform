from packages.security_assurance.iso_mapping import map_finding_to_iso
from packages.security_assurance.models import Finding, FindingStatus, Severity


def test_iso_mapping_does_not_claim_certification() -> None:
    finding = Finding(
        title="Prompt leakage",
        description="Canary leaked",
        root_cause="Prompt boundary failure",
        category="Prompt Injection",
        affected_component="System prompt",
        severity=Severity.high,
        likelihood=8,
        technical_impact=8,
        business_impact=7,
        confidence=0.95,
        reproducibility=9,
        status=FindingStatus.confirmed,
        evidence_references=["hash"],
        related_executions=["exec"],
        remediation="Fix prompt boundary",
        residual_risk="Retest",
        owner="owner",
    )
    mapping = map_finding_to_iso(finding)
    assert "certified" not in mapping.mapping_rationale.lower()
    assert mapping.human_review_status == "required"

