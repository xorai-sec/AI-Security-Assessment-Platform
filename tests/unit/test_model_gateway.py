from datetime import datetime

import httpx
import pytest

from packages.security_assurance.model_gateway import (
    InvocationEvidence,
    ModelGatewayError,
    ModelRoleConfig,
    ModelRoleGateway,
    redact_secrets,
)


def gateway(provider: str = "ollama") -> ModelRoleGateway:
    return ModelRoleGateway({"attacker": ModelRoleConfig(role="attacker", model="a", base_url="http://model:11434", provider=provider), "judge": ModelRoleConfig(role="judge", model="j", base_url="http://judge:8000/v1", provider="openai_compatible")}, distinct=True)


def response(payload: dict) -> httpx.Response:
    return httpx.Response(200, json=payload, request=httpx.Request("POST", "http://model"))


def test_ollama_request_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}
    monkeypatch.setattr(httpx, "post", lambda url, **kwargs: (seen.update({"url": url, "json": kwargs["json"]}) or response({"response": "ok", "eval_count": 2})))
    text, evidence = gateway().invoke("attacker", "hello")
    assert text == "ok"
    assert seen["url"].endswith("/api/generate")
    assert seen["json"]["stream"] is False
    assert isinstance(evidence, InvocationEvidence)


def test_openai_compatible_request_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}
    monkeypatch.setattr(httpx, "post", lambda url, **kwargs: (seen.update({"url": url, "json": kwargs["json"]}) or response({"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 3}})))
    text, evidence = gateway("openai_compatible").invoke("judge", "hello")
    assert text == "ok"
    assert seen["url"].endswith("/chat/completions")
    assert seen["json"]["messages"][0]["content"] == "hello"
    assert evidence.token_usage == {"total_tokens": 3}


def test_timeout_and_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "post", lambda *_args, **_kwargs: (_ for _ in ()).throw(httpx.ReadTimeout("timeout")))
    with pytest.raises(ModelGatewayError, match="invocation failed"):
        gateway().invoke("attacker", "hello")
    with pytest.raises(ModelGatewayError, match="unavailable"):
        ModelRoleGateway({}).validate_required()


def test_malformed_json_and_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "post", lambda *_args, **_kwargs: response({"choices": [{"message": {"content": "not-json"}}]}))
    with pytest.raises(ModelGatewayError):
        gateway("openai_compatible").invoke("judge", "hello", json_response=True)
    config = ModelRoleConfig(role="attacker", model="a", base_url="http://model", max_output_chars=2)
    monkeypatch.setattr(httpx, "post", lambda *_args, **_kwargs: response({"choices": [{"message": {"content": "long"}}]}))
    with pytest.raises(ModelGatewayError):
        ModelRoleGateway({"attacker": config}).invoke("attacker", "hello")


def test_redaction_distinct_roles_and_evidence() -> None:
    assert redact_secrets({"Authorization": "Bearer secret", "nested": {"token": "x"}}) == {"Authorization": "[REDACTED]", "nested": {"token": "[REDACTED]"}}
    with pytest.raises(ModelGatewayError, match="distinct"):
        ModelRoleGateway({"attacker": ModelRoleConfig(role="attacker", model="same", base_url="http://a"), "judge": ModelRoleConfig(role="judge", model="same", base_url="http://b")}).validate_required()
    now = datetime.now()
    assert now is not None
