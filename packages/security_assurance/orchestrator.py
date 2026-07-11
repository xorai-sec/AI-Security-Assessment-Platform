from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .campaigns import NATIVE_CAMPAIGNS, NativeCampaign
from .correlation import correlate_findings
from .enterprise_client import EnterpriseAssistClient
from .evaluation import evaluate_campaign
from .evidence import evidence_hash, redact_text
from .iso_mapping import map_finding_to_iso
from .models import (
    AssessmentResult,
    AssessmentScope,
    AttackExecution,
    CampaignSpec,
    Finding,
    FindingStatus,
    Severity,
)
from .reporting import write_reports
from .risk import calculate_risk
from .storage import EvidenceStore


def _build_finding(campaign: NativeCampaign, execution: AttackExecution, owner: str) -> Finding:
    risk = calculate_risk(
        likelihood=8.0,
        technical_impact=8.0,
        business_impact=7.0,
        reproducibility=9.0,
        detectability=4.0,
    )
    severity = Severity(risk["severity"])
    return Finding(
        title=f"{campaign.objective}",
        description=f"Controlled attack succeeded against {campaign.affected_component}.",
        root_cause=campaign.root_cause,
        category=campaign.category,
        affected_component=campaign.affected_component,
        severity=severity,
        likelihood=8.0,
        technical_impact=8.0,
        business_impact=7.0,
        confidence=execution.confidence,
        reproducibility=9.0,
        status=FindingStatus.confirmed,
        evidence_references=[execution.evidence_hash],
        related_executions=[execution.id],
        remediation=campaign.remediation,
        residual_risk="Retest required after remediation.",
        owner=owner,
    )


class AssessmentOrchestrator:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def run_native_assessment(self, scope: AssessmentScope, target_mode: str = "vulnerable") -> AssessmentResult:
        scope.validate_authorized()
        client = EnterpriseAssistClient(scope.target_url)
        result = AssessmentResult(scope=scope, target_mode=target_mode)

        for index, campaign in enumerate(NATIVE_CAMPAIGNS, start=1):
            if index > scope.max_requests:
                break
            spec = CampaignSpec(
                assessment_id=result.id,
                framework="native",
                attack_category=campaign.category,
                objective=campaign.objective,
                strategy="deterministic_controlled_canary",
            )
            payload = {
                "message": campaign.prompt,
                "user_role": campaign.user_role,
                "user_id": f"tester-{campaign.user_role}",
                "session_id": f"{result.id}-{campaign.key}",
                "mode": target_mode,
                "confirm_external_action": False,
            }
            response, latency_ms = client.chat(payload)
            evaluation = evaluate_campaign(campaign, response)
            evidence = {
                "campaign": campaign.key,
                "payload": payload,
                "response": response,
                "evaluation": evaluation,
            }
            execution = AttackExecution(
                campaign_id=spec.id,
                framework="native",
                framework_version="0.1.0",
                target=scope.target_url,
                prompt=campaign.prompt,
                response=redact_text(str(response.get("response", ""))),
                retrieval_trace=response.get("telemetry", {}).get("retrieval_trace", []),
                tool_trace=response.get("telemetry", {}).get("tool_trace", []),
                authorization_trace=response.get("telemetry", {}).get("authorization_trace", []),
                evaluator_results=[evaluation],
                success=bool(evaluation["success"]),
                confidence=float(evaluation["confidence"]),
                latency_ms=latency_ms,
                evidence_hash=evidence_hash(evidence),
            )
            result.executions.append(execution)
            self.store.save_json(f"{result.id}-{execution.id}.evidence.json", evidence)
            if execution.success:
                result.findings.append(_build_finding(campaign, execution, scope.system_owner))

        result.findings = correlate_findings(result.findings)
        result.iso_mappings = [map_finding_to_iso(finding) for finding in result.findings]
        result.completed_at = datetime.now(timezone.utc)
        result.reports = write_reports(result, self.store.report_dir)
        self.store.save_result(result)
        return result


def default_orchestrator(root: Path) -> AssessmentOrchestrator:
    return AssessmentOrchestrator(EvidenceStore(root))

