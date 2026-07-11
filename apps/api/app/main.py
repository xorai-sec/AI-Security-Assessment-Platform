from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, ValidationError

from packages.security_assurance.enterprise_client import EnterpriseAssistClient
from packages.security_assurance.framework_manager import FrameworkManager
from packages.security_assurance.framework_models import FrameworkAssessmentRequest
from packages.security_assurance.models import AISystem, AssessmentScope, EnvironmentType, Organization
from packages.security_assurance.orchestrator import default_orchestrator
from packages.security_assurance.storage import EvidenceStore
from packages.security_assurance.target_manager import TargetCreateRequest, TargetManager
from packages.security_assurance.target_models import TargetConfiguration, TargetCredential, TargetMessageRequest, TargetType


ROOT = Path(__file__).resolve().parents[3]
STORE = EvidenceStore(ROOT)
ORCHESTRATOR = default_orchestrator(ROOT)
TARGETS = TargetManager(ROOT)
FRAMEWORKS = FrameworkManager(ROOT, TARGETS)
TARGET_PROXY_SECRET = os.getenv("TARGET_PROXY_SECRET", "development-target-proxy-secret")


class DemoAssessmentRequest(BaseModel):
    target_url: str = os.getenv("ENTERPRISE_ASSIST_LOCAL_URL", "http://127.0.0.1:8090")
    mode: str = "vulnerable"
    organization_name: str = "Contoso Global"
    authorized_tester: str = "authorized-demo-tester"
    system_owner: str = "AI Platform Owner"
    max_requests: int = 20


class TargetAssessmentRequest(BaseModel):
    target_id: str
    assessment_name: str | None = None
    authorized_tester: str = "authorized-assessor"
    target_mode: str = "authorized"
    max_requests: int = 20
    written_authorization_confirmed: bool = True


class TestMessageRequest(BaseModel):
    prompt: str = "Reply with READY only."


app = FastAPI(
    title="AI Security Assessment and ISO/IEC 42001 Assurance Platform API",
    version="0.1.0",
    description="Controlled AI security assessment API. Does not certify ISO conformity.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, Any]:
    adapters = {
        item.id: {"status": item.health, "version": item.version, "enabled": item.enabled, "worker_url": item.worker_url}
        for item in FRAMEWORKS.list_frameworks()
    }
    return {"status": "ok", "service": "api", "adapters": adapters}


@app.get("/api/adapters/health")
def adapter_health() -> dict[str, Any]:
    return health()["adapters"]


@app.get("/api/frameworks")
def list_frameworks() -> dict[str, Any]:
    return {"frameworks": [item.model_dump(mode="json") for item in FRAMEWORKS.list_frameworks()]}


@app.post("/api/frameworks/health")
def framework_health() -> dict[str, Any]:
    return {"frameworks": FRAMEWORKS.health()}


@app.get("/api/frameworks/capabilities")
def framework_capabilities() -> dict[str, Any]:
    return {"frameworks": FRAMEWORKS.capabilities()}


@app.post("/api/frameworks/self-test/{framework_id}")
def framework_self_test(framework_id: str) -> dict[str, Any]:
    if framework_id not in {item.id for item in FRAMEWORKS.list_frameworks()}:
        raise HTTPException(status_code=404, detail="Framework not found")
    return {"framework": framework_id, "health": FRAMEWORKS.health().get(framework_id), "capabilities": FRAMEWORKS.capabilities().get(framework_id)}


@app.post("/api/assessments/frameworks")
def run_framework_assessment(request: FrameworkAssessmentRequest) -> dict[str, Any]:
    try:
        result = FRAMEWORKS.run_assessment(request, os.getenv("API_INTERNAL_BASE_URL", "http://api:8080"))
        return result.model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/assessments/frameworks")
def list_framework_assessments() -> dict[str, Any]:
    return {"assessments": FRAMEWORKS.list_results()}


@app.get("/api/assessments/frameworks/{assessment_id}")
def get_framework_assessment(assessment_id: str) -> dict[str, Any]:
    try:
        result = FRAMEWORKS.load_result(assessment_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Framework assessment not found") from exc

    target_metadata: dict[str, Any] | None = None
    try:
        target = TARGETS.get_target(result.target_id)
        target_metadata = target.model_dump(mode="json")
        target_metadata.pop("credential", None)
    except FileNotFoundError:
        target_metadata = {"id": result.target_id, "target_name": "Target record not found"}

    framework_summaries = []
    for worker_result in result.worker_results:
        framework = worker_result.get("framework") or worker_result.get("framework_id") or worker_result.get("name") or "unknown"
        evidence = worker_result.get("evidence", [])
        findings = worker_result.get("findings", [])
        framework_summaries.append(
            {
                "framework": framework,
                "status": worker_result.get("status", "completed"),
                "version": worker_result.get("version"),
                "attempts": worker_result.get("attempts", worker_result.get("request_count", len(evidence))),
                "evidence_count": len(evidence),
                "finding_count": len(findings),
                "confirmed_count": sum(1 for item in findings if str(item.get("status", "")).lower() == "confirmed"),
                "candidate_count": sum(1 for item in findings if str(item.get("status", "")).lower() in {"candidate", "needs_review", "needs-review"}),
                "duration": worker_result.get("duration") or worker_result.get("duration_seconds"),
                "error_count": len(worker_result.get("errors", [])) if isinstance(worker_result.get("errors", []), list) else 1,
                "raw_artifacts": worker_result.get("artifacts", {}),
            }
        )

    payload = result.model_dump(mode="json")
    payload["assessment_type"] = "multi_framework"
    payload["target"] = target_metadata
    payload["framework_summaries"] = framework_summaries
    payload["correlated_findings"] = []
    payload["iso_mappings"] = [
        {
            "id": f"{result.id}-iso-42001-{index + 1}",
            "evidence_id": evidence.get("id") or evidence.get("evidence_id") or f"evidence-{index + 1}",
            "clause_or_control_id": evidence.get("iso_42001_control", "ISO/IEC 42001 governance evidence"),
            "requirement_title": evidence.get("risk_category", evidence.get("category", "AI security control evidence")),
            "evidence_sufficiency": "candidate",
            "human_review_status": "requires_human_review",
        }
        for index, evidence in enumerate(result.normalized_evidence)
    ]
    payload["report_links"] = {}
    payload["raw_artifact_references"] = [
        summary["raw_artifacts"] for summary in framework_summaries if summary.get("raw_artifacts")
    ]
    return payload


@app.post("/api/demo/seed")
def seed_demo() -> dict[str, Any]:
    org = Organization(
        name="Contoso Global",
        industry="Multinational professional services",
        country_or_region="Global",
        business_context="Internal employee AI assistant used for policy, HR and support workflows.",
        data_classifications=["public", "internal", "confidential", "restricted"],
    )
    system = AISystem(
        organization_id=org.id,
        name="EnterpriseAssist",
        description="Synthetic internal AI assistant with RAG, memory and mock tools.",
        business_purpose="Assist employees with policies, support tickets and internal knowledge.",
        system_owner="AI Platform Owner",
        deployment_status="local_lab",
        model_provider="deterministic_lab",
        model_name="enterprise-assist-simulator",
        model_endpoint=os.getenv("ENTERPRISE_ASSIST_LOCAL_URL", "http://127.0.0.1:8090"),
        system_type="RAG tool-using assistant",
        rag_enabled=True,
        memory_enabled=True,
        tool_use_enabled=True,
        human_oversight_description="External actions require explicit confirmation in hardened mode.",
        data_sources=["synthetic policies", "synthetic HR records", "synthetic project summaries"],
        user_roles=["standard_employee", "department_manager", "compliance_reviewer", "system_administrator"],
        critical_actions=["mock_email", "support_ticket"],
        architecture_metadata={"lab_target": True, "synthetic_data_only": True},
    )
    STORE.save_json("demo-organization.json", org.model_dump(mode="json"))
    STORE.save_json("demo-ai-system.json", system.model_dump(mode="json"))
    return {"organization": org, "ai_system": system}


@app.post("/api/demo/register-enterprise-assist")
def register_enterprise_assist() -> dict[str, Any]:
    request = TargetCreateRequest(
        organization="Contoso Global",
        system_name="EnterpriseAssist",
        target_name="EnterpriseAssist vulnerable/hardened laboratory target",
        target_type=TargetType.enterprise_assist,
        business_purpose="Synthetic internal assistant used as a safe regression and presentation target.",
        system_owner="AI Platform Owner",
        technical_owner="AI Platform Engineering",
        target_version="0.1.0",
        model_provider="deterministic_lab",
        model_name="enterprise-assist-simulator",
        deployment_type="local",
        criticality="medium",
        data_classification="synthetic confidential lab data",
        configuration=TargetConfiguration(
            base_url=os.getenv("ENTERPRISE_ASSIST_LOCAL_URL", "http://127.0.0.1:8090"),
            health_path="/health",
            chat_path="/chat",
        ),
        credential=TargetCredential(authentication_type="none"),
        authorization_confirmed=True,
        kill_switch_acknowledged=True,
        allowed_testing_categories=[
            "Prompt Injection",
            "Indirect Prompt Injection",
            "Unauthorized Retrieval",
            "Unauthorized Tool Execution",
            "Confirmation Bypass",
            "Memory Isolation",
        ],
    )
    target = TARGETS.create_target(request)
    health_result = TARGETS.health_check(target.id)
    capabilities = TARGETS.discover_capabilities(target.id)
    return {"target": TARGETS.get_target(target.id).model_dump(mode="json"), "health": health_result, "capabilities": capabilities}


@app.get("/api/targets")
def list_targets() -> dict[str, Any]:
    return {"targets": [TARGETS.mask_target(target).model_dump(mode="json") for target in TARGETS.list_targets()]}


@app.post("/api/targets")
def create_target(request: TargetCreateRequest) -> dict[str, Any]:
    target = TARGETS.create_target(request)
    return {"target": target.model_dump(mode="json")}


@app.get("/api/targets/{target_id}")
def get_target(target_id: str) -> dict[str, Any]:
    try:
        return {"target": TARGETS.mask_target(TARGETS.get_target(target_id)).model_dump(mode="json")}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.patch("/api/targets/{target_id}")
def update_target(target_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    try:
        return {"target": TARGETS.update_target(target_id, patch).model_dump(mode="json")}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.delete("/api/targets/{target_id}")
def disable_target(target_id: str) -> dict[str, Any]:
    try:
        return {"target": TARGETS.disable_target(target_id).model_dump(mode="json")}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.post("/api/targets/{target_id}/validate")
def validate_target(target_id: str) -> dict[str, Any]:
    try:
        return TARGETS.validate_target(target_id).model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.post("/api/targets/{target_id}/health-check")
def target_health_check(target_id: str) -> dict[str, Any]:
    try:
        return TARGETS.health_check(target_id).model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.post("/api/targets/{target_id}/discover-capabilities")
def discover_target_capabilities(target_id: str) -> dict[str, Any]:
    try:
        return TARGETS.discover_capabilities(target_id).model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.post("/api/targets/{target_id}/test-message")
def target_test_message(target_id: str, request: TestMessageRequest) -> dict[str, Any]:
    try:
        return TARGETS.test_message(target_id, request.prompt).model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.get("/api/targets/{target_id}/supported-campaigns")
def supported_campaigns(target_id: str) -> dict[str, Any]:
    try:
        return {"campaigns": [row.model_dump(mode="json") for row in TARGETS.supported_campaigns(target_id)]}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc


@app.get("/api/targets/{target_id}/health-history")
def target_health_history(target_id: str) -> dict[str, Any]:
    return {"history": TARGETS.health_history(target_id)}


def _check_internal_token(x_target_proxy_token: str | None) -> None:
    if x_target_proxy_token != TARGET_PROXY_SECRET:
        raise HTTPException(status_code=403, detail="Invalid internal target proxy token")


@app.post("/internal/targets/{target_id}/sessions")
def internal_create_session(target_id: str, x_target_proxy_token: str | None = Header(default=None)) -> dict[str, Any]:
    _check_internal_token(x_target_proxy_token)
    TARGETS.get_target(target_id)
    return {"session_id": f"SES-{target_id}"}


@app.post("/internal/targets/{target_id}/message")
async def internal_target_message(
    target_id: str,
    request: dict[str, Any],
    x_target_proxy_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_internal_token(x_target_proxy_token)
    try:
        return await FRAMEWORKS.proxy_target_message(target_id, request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/internal/targets/{target_id}/reset")
def internal_target_reset(target_id: str, x_target_proxy_token: str | None = Header(default=None)) -> dict[str, Any]:
    _check_internal_token(x_target_proxy_token)
    TARGETS.get_target(target_id)
    return {"target_id": target_id, "status": "reset-not-required"}


@app.get("/internal/targets/{target_id}/telemetry/{request_id}")
def internal_target_telemetry(
    target_id: str,
    request_id: str,
    x_target_proxy_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_internal_token(x_target_proxy_token)
    TARGETS.get_target(target_id)
    return {"target_id": target_id, "request_id": request_id, "telemetry": {}, "unavailable": ["telemetry lookup not exposed by target"]}


@app.post("/internal/framework-events")
def internal_framework_events(event: dict[str, Any], x_target_proxy_token: str | None = Header(default=None)) -> dict[str, Any]:
    _check_internal_token(x_target_proxy_token)
    path = ROOT / "data" / "framework-events.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        import json

        handle.write(json.dumps(event, default=str) + "\n")
    return {"stored": True}


@app.post("/api/assessments/demo")
def run_demo_assessment(request: DemoAssessmentRequest) -> dict[str, Any]:
    try:
        EnterpriseAssistClient(request.target_url).health()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Target health check failed: {exc}") from exc
    scope = AssessmentScope(
        assessment_name=f"EnterpriseAssist {request.mode} controlled assessment",
        organization_name=request.organization_name,
        target_name="EnterpriseAssist",
        target_url=request.target_url,
        environment_type=EnvironmentType.local_lab,
        system_owner=request.system_owner,
        authorized_tester=request.authorized_tester,
        testing_start=datetime.now(timezone.utc),
        testing_end=datetime.now(timezone.utc) + timedelta(hours=1),
        allowed_attack_categories=[
            "Prompt Injection",
            "Indirect Prompt Injection",
            "Unauthorized Retrieval",
            "Unauthorized Tool Execution",
            "Confirmation Bypass",
            "Memory Isolation",
        ],
        disallowed_activities=[
            "denial of service",
            "public target scanning",
            "real external email",
            "credential attacks",
            "malware deployment",
        ],
        data_classification="synthetic confidential lab data",
        written_authorization_confirmed=True,
        production=False,
        rate_limit_seconds=0.2,
        max_requests=request.max_requests,
        max_duration_seconds=1800,
    )
    result = ORCHESTRATOR.run_native_assessment(scope, target_mode=request.mode)
    return result.model_dump(mode="json")


@app.post("/api/assessments/target")
async def run_target_assessment(request: TargetAssessmentRequest) -> dict[str, Any]:
    try:
        target = TARGETS.get_target(request.target_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Target not found") from exc
    if not target.enabled:
        raise HTTPException(status_code=400, detail=f"Target is disabled: {target.disabled_reason}")
    if not request.written_authorization_confirmed or not target.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Written authorization must be confirmed before assessment.")
    if not target.kill_switch_acknowledged:
        raise HTTPException(status_code=400, detail="Kill-switch acknowledgement is required before assessment.")
    target_health = await TARGETS.health_check_async(target.id)
    if not target_health.reachable:
        raise HTTPException(status_code=400, detail=f"Target health check failed: {target_health.message}")
    capabilities = await TARGETS.discover_capabilities_async(target.id)
    target = TARGETS.get_target(target.id)
    scope = AssessmentScope(
        assessment_name=request.assessment_name or f"{target.target_name} native controlled assessment",
        organization_name=target.organization,
        target_name=target.target_name,
        target_url=target.configuration.base_url or target.id,
        environment_type=target.environment,
        system_owner=target.system_owner,
        authorized_tester=request.authorized_tester,
        testing_start=datetime.now(timezone.utc),
        testing_end=datetime.now(timezone.utc) + timedelta(seconds=target.max_duration_seconds),
        allowed_attack_categories=target.allowed_testing_categories or [row.category for row in TARGETS.supported_campaigns(target.id) if row.supported],
        disallowed_activities=target.prohibited_actions,
        data_classification=target.data_classification,
        written_authorization_confirmed=True,
        production=target.deployment_type == "production",
        rate_limit_seconds=0.2,
        max_requests=min(request.max_requests, target.max_requests),
        max_duration_seconds=target.max_duration_seconds,
    )
    result = await ORCHESTRATOR.run_native_assessment_for_target(scope, target, target_mode=request.target_mode)
    target.last_assessment_id = result.id
    TARGETS.update_target(target.id, {"last_assessment_id": result.id})
    payload = result.model_dump(mode="json")
    payload["target_capabilities"] = capabilities.model_dump(mode="json")
    return payload


@app.get("/api/assessments")
def list_assessments() -> dict[str, Any]:
    return {"assessments": STORE.list_results()}


@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str) -> dict[str, Any]:
    try:
        return STORE.load_result(assessment_id).model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Assessment not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Stored assessment result is malformed or incomplete") from exc


@app.get("/api/reports/{assessment_id}/markdown", response_class=PlainTextResponse)
def report_markdown(assessment_id: str) -> str:
    path = STORE.report_dir / f"{assessment_id}.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return path.read_text(encoding="utf-8")


@app.get("/api/reports/{assessment_id}/{kind}")
def report_file(assessment_id: str, kind: str) -> FileResponse:
    suffix = {"html": ".html", "json": ".json", "csv": "-findings.csv"}.get(kind)
    if suffix is None:
        raise HTTPException(status_code=400, detail="kind must be html, json or csv")
    path = STORE.report_dir / f"{assessment_id}{suffix}"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path)
