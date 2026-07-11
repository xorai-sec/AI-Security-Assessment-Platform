from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from packages.security_assurance.enterprise_client import EnterpriseAssistClient
from packages.security_assurance.models import AISystem, AssessmentScope, EnvironmentType, Organization
from packages.security_assurance.orchestrator import default_orchestrator
from packages.security_assurance.storage import EvidenceStore


ROOT = Path(__file__).resolve().parents[3]
STORE = EvidenceStore(ROOT)
ORCHESTRATOR = default_orchestrator(ROOT)


class DemoAssessmentRequest(BaseModel):
    target_url: str = os.getenv("ENTERPRISE_ASSIST_LOCAL_URL", "http://127.0.0.1:8090")
    mode: str = "vulnerable"
    organization_name: str = "Contoso Global"
    authorized_tester: str = "authorized-demo-tester"
    system_owner: str = "AI Platform Owner"
    max_requests: int = 20


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
        "native": {"status": "Available", "version": "0.1.0"},
        "garak": {"status": "Planned", "version": None},
        "pyrit": {"status": "Planned", "version": None},
        "promptfoo": {"status": "Planned", "version": None},
        "deepteam": {"status": "Planned", "version": None},
    }
    return {"status": "ok", "service": "api", "adapters": adapters}


@app.get("/api/adapters/health")
def adapter_health() -> dict[str, Any]:
    return health()["adapters"]


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


@app.get("/api/assessments")
def list_assessments() -> dict[str, Any]:
    return {"assessments": STORE.list_results()}


@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str) -> dict[str, Any]:
    try:
        return STORE.load_result(assessment_id).model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Assessment not found") from exc


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
