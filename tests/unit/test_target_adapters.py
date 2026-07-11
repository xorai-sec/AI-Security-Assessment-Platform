import asyncio

from packages.security_assurance.adapters.targets.base import field_get, field_set
from packages.security_assurance.adapters.targets.custom_rest import CustomRESTTargetAdapter
from packages.security_assurance.adapters.targets.openai_compatible import OpenAICompatibleTargetAdapter
from packages.security_assurance.target_models import TargetConfiguration


def test_field_get_supports_list_indexes() -> None:
    data = {"choices": [{"message": {"content": "hello"}}]}
    assert field_get(data, "choices.0.message.content") == "hello"


def test_field_set_nested_path() -> None:
    data = {}
    field_set(data, "input.prompt", "test")
    assert data == {"input": {"prompt": "test"}}


def test_openai_capability_discovery() -> None:
    adapter = OpenAICompatibleTargetAdapter(
        TargetConfiguration(base_url="http://localhost:8090", model_name="fixture", chat_path="/v1/chat/completions")
    )
    caps = asyncio.run(adapter.discover_capabilities())
    assert caps.chat
    assert caps.openai_compatible
    assert caps.black_box


def test_custom_rest_requires_response_path() -> None:
    adapter = CustomRESTTargetAdapter(
        TargetConfiguration(base_url="http://localhost:8090", chat_path="/custom-chat", response_text_path="")
    )
    result = asyncio.run(adapter.validate_configuration())
    assert not result.valid
    assert any("response_text_path" in error for error in result.errors)

