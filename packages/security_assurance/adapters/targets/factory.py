from __future__ import annotations

from ...target_models import TargetRecord, TargetType
from .base import AITargetAdapter
from .custom_rest import CustomRESTTargetAdapter
from .enterprise_assist import EnterpriseAssistTargetAdapter
from .ollama import OllamaTargetAdapter
from .openai_compatible import OpenAICompatibleTargetAdapter, VLLMTargetAdapter


def build_target_adapter(target: TargetRecord) -> AITargetAdapter:
    if target.target_type == TargetType.enterprise_assist:
        return EnterpriseAssistTargetAdapter(target.configuration, target.credential)
    if target.target_type == TargetType.openai_compatible:
        return OpenAICompatibleTargetAdapter(target.configuration, target.credential)
    if target.target_type == TargetType.vllm:
        return VLLMTargetAdapter(target.configuration, target.credential)
    if target.target_type == TargetType.ollama:
        return OllamaTargetAdapter(target.configuration, target.credential)
    if target.target_type in {TargetType.custom_rest, TargetType.generic_rag, TargetType.generic_agent}:
        return CustomRESTTargetAdapter(target.configuration, target.credential)
    raise ValueError(f"Unsupported target type: {target.target_type}")

