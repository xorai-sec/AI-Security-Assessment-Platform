from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .campaigns import NATIVE_CAMPAIGNS
from .models import utc_now
from .target_models import (
    ConfigurationValidationResult,
    SupportedCampaign,
    TargetCapabilities,
    TargetConfiguration,
    TargetCredential,
    TargetHealth,
    TargetMessageRequest,
    TargetMessageResponse,
    TargetRecord,
    TargetType,
    TargetVisibility,
)
from .target_security import DevelopmentCredentialProtector
from .adapters.targets import build_target_adapter


CAMPAIGN_REQUIREMENTS: dict[str, set[str]] = {
    "system_prompt_leakage": {"chat"},
    "indirect_rag_injection": {"chat", "rag"},
    "unauthorized_document_retrieval": {"chat", "rag"},
    "unauthorized_tool_execution": {"chat", "tools"},
    "external_action_confirmation_bypass": {"chat", "tools", "confirmation_workflow"},
    "cross_session_memory_leakage": {"chat", "memory"},
}


class TargetCreateRequest(BaseModel):
    organization: str = "Contoso Global"
    system_name: str = "Registered AI System"
    target_name: str
    target_type: TargetType
    environment: str = "local_lab"
    business_purpose: str = ""
    system_owner: str = "AI Platform Owner"
    technical_owner: str = ""
    target_version: str = "unknown"
    model_provider: str = "unknown"
    model_name: str = "unknown"
    deployment_type: str = "local"
    criticality: str = "medium"
    data_classification: str = "synthetic"
    configuration: TargetConfiguration
    credential: TargetCredential = Field(default_factory=TargetCredential)
    secret: str | None = None
    declared_capabilities: TargetCapabilities = Field(default_factory=TargetCapabilities)
    authorization_confirmed: bool = False
    max_requests: int = 20
    max_duration_seconds: int = 1800
    max_concurrency: int = 1
    allowed_testing_categories: list[str] = Field(default_factory=list)
    emergency_contact: str = ""
    kill_switch_acknowledged: bool = False
    save_disabled_draft: bool = False


class TargetManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.target_dir = root / "data" / "targets"
        self.health_dir = root / "data" / "target-health"
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.health_dir.mkdir(parents=True, exist_ok=True)
        self.credential_protector = DevelopmentCredentialProtector()

    def list_targets(self) -> list[TargetRecord]:
        targets = []
        for path in sorted(self.target_dir.glob("TGT-*.json")):
            targets.append(TargetRecord.model_validate_json(path.read_text(encoding="utf-8")))
        return targets

    def get_target(self, target_id: str) -> TargetRecord:
        path = self._target_path(target_id)
        return TargetRecord.model_validate_json(path.read_text(encoding="utf-8"))

    def create_target(self, request: TargetCreateRequest) -> TargetRecord:
        credential = request.credential.model_copy(deep=True)
        if request.secret:
            credential.secret_encrypted = self.credential_protector.encrypt(request.secret)
            credential.secret_preview = self.credential_protector.preview(request.secret)
        target = TargetRecord(
            organization=request.organization,
            system_name=request.system_name,
            target_name=request.target_name,
            target_type=request.target_type,
            environment=request.environment,
            business_purpose=request.business_purpose,
            system_owner=request.system_owner,
            technical_owner=request.technical_owner,
            target_version=request.target_version,
            model_provider=request.model_provider,
            model_name=request.model_name,
            deployment_type=request.deployment_type,
            criticality=request.criticality,
            data_classification=request.data_classification,
            configuration=request.configuration,
            credential=credential,
            declared_capabilities=request.declared_capabilities,
            authorization_confirmed=request.authorization_confirmed,
            max_requests=request.max_requests,
            max_duration_seconds=request.max_duration_seconds,
            max_concurrency=request.max_concurrency,
            allowed_testing_categories=request.allowed_testing_categories,
            emergency_contact=request.emergency_contact,
            kill_switch_acknowledged=request.kill_switch_acknowledged,
        )
        if request.save_disabled_draft:
            target.enabled = False
            target.disabled_reason = "Saved as disabled draft before validation."
        else:
            validation = self.validate_target(target.id, target_override=target)
            target.enabled = validation.valid and target.authorization_confirmed and target.kill_switch_acknowledged
            if not target.enabled:
                target.disabled_reason = "; ".join(validation.errors) or "Authorization and kill-switch acknowledgement are required."
        self._save_target(target)
        return self.mask_target(target)

    def update_target(self, target_id: str, patch: dict[str, Any]) -> TargetRecord:
        target = self.get_target(target_id)
        data = target.model_dump(mode="json")
        for key, value in patch.items():
            if key == "secret":
                data["credential"]["secret_encrypted"] = self.credential_protector.encrypt(str(value))
                data["credential"]["secret_preview"] = self.credential_protector.preview(str(value))
            elif key in data:
                data[key] = value
        data["updated_at"] = utc_now().isoformat()
        target = TargetRecord.model_validate(data)
        self._save_target(target)
        return self.mask_target(target)

    def disable_target(self, target_id: str) -> TargetRecord:
        target = self.get_target(target_id)
        target.enabled = False
        target.disabled_reason = "Soft deleted or disabled by user."
        target.updated_at = utc_now()
        self._save_target(target)
        return self.mask_target(target)

    def validate_target(self, target_id: str, target_override: TargetRecord | None = None) -> ConfigurationValidationResult:
        target = target_override or self.get_target(target_id)
        adapter = build_target_adapter(target)
        return asyncio.run(adapter.validate_configuration())

    def health_check(self, target_id: str) -> TargetHealth:
        target = self.get_target(target_id)
        adapter = build_target_adapter(target)
        health = asyncio.run(adapter.health_check())
        target.last_health = health
        target.updated_at = utc_now()
        self._save_target(target)
        self._save_health(target.id, health)
        return health

    def discover_capabilities(self, target_id: str) -> TargetCapabilities:
        target = self.get_target(target_id)
        adapter = build_target_adapter(target)
        capabilities = asyncio.run(adapter.discover_capabilities())
        target.discovered_capabilities = capabilities
        target.visibility = self._visibility_from_capabilities(capabilities)
        target.last_validated_at = utc_now()
        target.updated_at = utc_now()
        self._save_target(target)
        return capabilities

    def test_message(self, target_id: str, prompt: str = "Reply with READY only.") -> TargetMessageResponse:
        target = self.get_target(target_id)
        adapter = build_target_adapter(target)
        response = asyncio.run(adapter.send_message(TargetMessageRequest(prompt=prompt)))
        return asyncio.run(adapter.sanitize_for_storage(response))

    def supported_campaigns(self, target_id: str) -> list[SupportedCampaign]:
        target = self.get_target(target_id)
        capabilities = target.discovered_capabilities or target.declared_capabilities
        enabled = set(capabilities.enabled())
        rows: list[SupportedCampaign] = []
        for campaign in NATIVE_CAMPAIGNS:
            required = CAMPAIGN_REQUIREMENTS.get(campaign.key, {"chat"})
            missing = sorted(required - enabled)
            rows.append(
                SupportedCampaign(
                    key=campaign.key,
                    category=campaign.category,
                    supported=not missing,
                    evidence_basis=target.visibility.value,
                    missing_capabilities=missing,
                )
            )
        return rows

    def health_history(self, target_id: str) -> list[dict[str, Any]]:
        path = self.health_dir / f"{target_id}.jsonl"
        if not path.exists():
            return []
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            rows.append(TargetHealth.model_validate_json(line).model_dump(mode="json"))
        return rows

    def mask_target(self, target: TargetRecord) -> TargetRecord:
        masked = target.model_copy(deep=True)
        if masked.credential.secret_encrypted:
            masked.credential.secret_encrypted = None
        return masked

    def _target_path(self, target_id: str) -> Path:
        return self.target_dir / f"{target_id}.json"

    def _save_target(self, target: TargetRecord) -> None:
        self._target_path(target.id).write_text(target.model_dump_json(indent=2), encoding="utf-8")

    def _save_health(self, target_id: str, health: TargetHealth) -> None:
        path = self.health_dir / f"{target_id}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(health.model_dump_json() + "\n")

    def _visibility_from_capabilities(self, capabilities: TargetCapabilities) -> TargetVisibility:
        if capabilities.white_box:
            return TargetVisibility.white_box
        if capabilities.grey_box or capabilities.retrieval_telemetry or capabilities.tool_telemetry:
            return TargetVisibility.grey_box
        return TargetVisibility.black_box

