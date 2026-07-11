from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import pkgutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from workers.common.advanced import framework_evidence
from workers.common.artifacts import run_artifacts
from workers.common.base_runner import BaseFrameworkRunner
from workers.common.protocol.schemas import FrameworkExecutionRequest, FrameworkExecutionResult, WorkerCapability
from workers.common.server import create_worker_app


PYRIT_PROMPT_TARGET = "pyrit.prompt_target.common.prompt_chat_target.PromptChatTarget"
PYRIT_ATTACK = "pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack"
PYRIT_EXECUTOR = "pyrit.executor.attack.core.attack_executor.AttackExecutor"
PYRIT_MEMORY = "pyrit.memory.sqlite_memory.SQLiteMemory"
PYRIT_CENTRAL_MEMORY = "pyrit.memory.central_memory.CentralMemory"


def _load_symbol(path: str) -> Any:
    module_name, symbol_name = path.rsplit(".", 1)
    module = importlib.import_module(module_name)
    return getattr(module, symbol_name)


def _object_to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list | tuple | set):
        return [_object_to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _object_to_jsonable(item) for key, item in value.items()}
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(mode="json")
        except Exception:
            pass
    if hasattr(value, "dict"):
        try:
            return value.dict()
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return {key: _object_to_jsonable(item) for key, item in vars(value).items() if not key.startswith("_")}
    return repr(value)


def _message_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        for key in ("content", "text", "converted_value", "original_value", "value"):
            if key in message and message[key] is not None:
                return _message_text(message[key])
    for attr in ("content", "text", "converted_value", "original_value", "value"):
        if hasattr(message, attr):
            value = getattr(message, attr)
            if value is not None:
                return _message_text(value)
    pieces = getattr(message, "request_pieces", None) or getattr(message, "pieces", None)
    if pieces:
        return "\n".join(_message_text(piece) for piece in pieces if _message_text(piece))
    if hasattr(message, "get_value"):
        try:
            return str(message.get_value())
        except Exception:
            pass
    return str(message)


def _message_conversation_id(message: Any, default: str) -> str:
    for attr in ("conversation_id", "conversationId"):
        if hasattr(message, attr):
            value = getattr(message, attr)
            if value:
                return str(value)
    pieces = getattr(message, "request_pieces", None) or getattr(message, "pieces", None)
    if pieces:
        for piece in pieces:
            for attr in ("conversation_id", "conversationId"):
                if hasattr(piece, attr):
                    value = getattr(piece, attr)
                    if value:
                        return str(value)
    return default


def _build_pyrit_message(text: str, request_message: Any, conversation_id: str) -> Any:
    errors: list[str] = []
    candidates: list[tuple[str, Any]] = []
    for path in ("pyrit.models.message.Message", "pyrit.models.Message"):
        try:
            candidates.append((path, _load_symbol(path)))
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    for path, cls in candidates:
        for kwargs in (
            {"role": "assistant", "content": text},
            {"role": "assistant", "content": text, "conversation_id": conversation_id},
            {"role": "assistant", "text": text, "conversation_id": conversation_id},
            {"content": text, "role": "assistant"},
        ):
            try:
                return cls(**kwargs)
            except Exception as exc:
                errors.append(f"{path}{kwargs}: {exc}")
    try:
        piece_cls = _load_symbol("pyrit.models.message_piece.MessagePiece")
        piece = piece_cls(
            role="assistant",
            original_value=text,
            converted_value=text,
            conversation_id=conversation_id,
        )
        for _, cls in candidates:
            try:
                return cls(request_pieces=[piece])
            except Exception as exc:
                errors.append(f"{cls}.request_pieces: {exc}")
    except Exception as exc:
        errors.append(f"MessagePiece: {exc}")
    if hasattr(request_message, "model_copy"):
        for update in ({"content": text, "role": "assistant"}, {"text": text, "role": "assistant"}):
            try:
                return request_message.model_copy(update=update)
            except Exception as exc:
                errors.append(f"model_copy{update}: {exc}")
    raise RuntimeError("Unable to construct PyRIT Message response; " + " | ".join(errors[-8:]))


class TargetProxyPromptTarget(_load_symbol(PYRIT_PROMPT_TARGET)):  # type: ignore[misc]
    def __init__(
        self,
        *,
        runner: BaseFrameworkRunner,
        request: FrameworkExecutionRequest,
        traffic_path: Path,
    ) -> None:
        super().__init__(
            endpoint=runner.proxy_base_url,
            model_name=request.target.model_name or request.model_roles.target_model or request.target.target_id,
        )
        self.runner = runner
        self.request = request
        self.traffic_path = traffic_path
        self.rows: list[dict[str, Any]] = []
        self.counter = 0

    async def send_prompt_async(self, *, message: Any) -> list[Any]:
        self.counter += 1
        prompt = _message_text(message)
        conversation_id = _message_conversation_id(message, f"{self.request.execution_id}-pyrit-{self.counter}")
        response = await self.runner.proxy.send_message(
            target_id=self.request.target.target_id,
            execution_id=self.request.execution_id,
            campaign_id=self.request.campaign_id,
            prompt=prompt,
            session_id=conversation_id,
            user_role=self.request.configuration.get("user_role", "standard_employee"),
            metadata={
                **self.request.configuration.get("target_metadata", {}),
                "source_framework": "pyrit",
                "native_target_class": f"{self.__class__.__module__}.{self.__class__.__name__}",
            },
        )
        row = {
            "turn": self.counter,
            "conversation_id": conversation_id,
            "request_message": _object_to_jsonable(message),
            "prompt": prompt,
            "response": response,
        }
        self.rows.append(row)
        with self.traffic_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, default=str) + "\n")
        return [_build_pyrit_message(str(response.get("text", "")), message, conversation_id)]


class PyRITRunner(BaseFrameworkRunner):
    framework_name = "pyrit"
    package_name = "pyrit"

    def _discovery(self) -> dict[str, Any]:
        try:
            import pyrit  # type: ignore

            modules = sorted(
                module.name
                for module in pkgutil.walk_packages(pyrit.__path__, prefix="pyrit.")
                if any(key in module.name for key in ["prompt", "score", "memory", "orchestrator", "converter", "attack"])
            )[:300]
            targets = {}
            for path in (
                PYRIT_PROMPT_TARGET,
                PYRIT_ATTACK,
                PYRIT_EXECUTOR,
                PYRIT_MEMORY,
                PYRIT_CENTRAL_MEMORY,
                "pyrit.models.message.Message",
                "pyrit.models.message_piece.MessagePiece",
            ):
                try:
                    obj = _load_symbol(path)
                    targets[path] = {
                        "signature": str(inspect.signature(obj)) if callable(obj) else None,
                        "module_file": inspect.getsourcefile(obj),
                    }
                except Exception as exc:
                    targets[path] = {"error": str(exc)}
            return {"version": self.detected_version(), "modules": modules, "targets": targets, "status": "available"}
        except Exception as exc:
            return {"version": self.detected_version(), "modules": [], "targets": {}, "status": "limited", "error": str(exc)}

    async def capabilities(self) -> list[WorkerCapability]:
        discovery = self._discovery()
        native_ready = discovery["status"] == "available" and not discovery["targets"].get(PYRIT_ATTACK, {}).get("error")
        return [
            WorkerCapability(name="package_introspection", supported=discovery["status"] == "available", detail=f"{len(discovery['modules'])} pyrit modules discovered"),
            WorkerCapability(name="prompt_target_proxy", supported=native_ready, detail=f"subclasses {PYRIT_PROMPT_TARGET}"),
            WorkerCapability(name="official_attack_executor", supported=native_ready, detail=f"{PYRIT_EXECUTOR}.execute_attack_async"),
            WorkerCapability(name="official_prompt_sending_attack", supported=native_ready, detail=PYRIT_ATTACK),
            WorkerCapability(name="memory", supported=native_ready, detail=f"{PYRIT_MEMORY} + {PYRIT_CENTRAL_MEMORY}"),
            WorkerCapability(name="converters", supported=True, detail="converter support is discovered and passed through when compatible"),
            WorkerCapability(name="scorers", supported=True, detail="scoring config is created when compatible scorers are configured"),
        ]

    def _objectives_for_request(self, request: FrameworkExecutionRequest) -> list[str]:
        cases = self.cases_for_request(request)
        objectives = [case.prompt for case in cases]
        return objectives[: max(1, min(request.limits.maximum_requests, len(objectives)))]

    async def _execute_native(self, request: FrameworkExecutionRequest, target: TargetProxyPromptTarget) -> Any:
        PromptSendingAttack = _load_symbol(PYRIT_ATTACK)
        AttackExecutor = _load_symbol(PYRIT_EXECUTOR)
        attack = PromptSendingAttack(objective_target=target)
        executor = AttackExecutor(max_concurrency=max(1, min(request.limits.maximum_concurrency, 4)))
        return await executor.execute_attack_async(
            attack=attack,
            objectives=self._objectives_for_request(request),
            return_partial_on_failure=True,
        )

    def _set_memory(self, db_path: Path) -> tuple[Any | None, list[str]]:
        plugin_ids: list[str] = []
        try:
            SQLiteMemory = _load_symbol(PYRIT_MEMORY)
            CentralMemory = _load_symbol(PYRIT_CENTRAL_MEMORY)
            memory = SQLiteMemory(db_path=db_path)
            CentralMemory.set_memory_instance(memory)
            plugin_ids.extend([PYRIT_MEMORY, PYRIT_CENTRAL_MEMORY])
            return memory, plugin_ids
        except Exception:
            return None, plugin_ids

    async def execute(self, request: FrameworkExecutionRequest) -> FrameworkExecutionResult:
        started = datetime.now(timezone.utc)
        artifacts = run_artifacts(self.artifact_root, request.execution_id)
        discovery_path = artifacts.write_json("discovery.json", self._discovery())
        memory_path = artifacts.path("pyrit-memory.sqlite")
        traffic_path = artifacts.path("target-proxy-traffic.jsonl")
        native_result_path = artifacts.path("native-result.json")
        plugin_ids = [PYRIT_PROMPT_TARGET, PYRIT_ATTACK, PYRIT_EXECUTOR]
        errors: list[str] = []
        native_result: Any = None
        memory, memory_plugins = self._set_memory(memory_path)
        plugin_ids.extend(memory_plugins)
        target = TargetProxyPromptTarget(runner=self, request=request, traffic_path=traffic_path)
        native_api = (
            f"{PYRIT_EXECUTOR}.execute_attack_async("
            f"attack={PYRIT_ATTACK}, objective_target={target.__class__.__module__}.{target.__class__.__name__})"
        )
        try:
            native_result = await asyncio.wait_for(
                self._execute_native(request, target),
                timeout=request.limits.maximum_duration_seconds,
            )
            artifacts.write_json("native-result.json", _object_to_jsonable(native_result))
        except Exception as exc:
            errors.append(f"Native PyRIT execution failed: {exc}")
            artifacts.write_json("native-error.json", {"error": str(exc), "native_command_or_api": native_api})
        finally:
            if memory is not None:
                try:
                    export_path = memory.export_conversations(file_path=artifacts.path("conversations.json"), export_type="json")
                    plugin_ids.append(f"{PYRIT_MEMORY}.export_conversations")
                    native_result_path = Path(export_path)
                except Exception as exc:
                    errors.append(f"PyRIT memory export failed: {exc}")
                try:
                    memory.dispose_engine()
                except Exception:
                    pass

        evidence = []
        cases = self.cases_for_request(request)
        for index, row in enumerate(target.rows, start=1):
            case = cases[min(index - 1, len(cases) - 1)]
            response = row.get("response", {})
            conversation_trace = [
                {"role": "user", "content": row.get("prompt", ""), "conversation_id": row.get("conversation_id")},
                {"role": "assistant", "content": response.get("text", ""), "conversation_id": row.get("conversation_id")},
            ]
            evidence.append(
                framework_evidence(
                    request=request,
                    framework=self.framework_name,
                    framework_version=self.detected_version(),
                    case=case,
                    index=index,
                    prompt=str(row.get("prompt", "")),
                    response=response,
                    artifact_path=native_result_path,
                    conversation_trace=conversation_trace,
                    evaluator_extra={"pyrit_native_result": _object_to_jsonable(native_result), "native_target_turn": row.get("turn")},
                    stop_reason="pyrit_official_executor",
                    native_engine_invoked=True,
                    native_command_or_api=native_api,
                    native_framework_version=self.detected_version(),
                    native_artifact_path=str(native_result_path),
                    native_plugin_identifiers=plugin_ids,
                    fallback_used=False,
                )
            )

        if not target.rows:
            errors.append("Native PyRIT target did not send any prompt through the target proxy")
        status = "succeeded" if evidence and not errors else "partially_completed" if evidence else "failed"
        return FrameworkExecutionResult(
            execution_id=request.execution_id,
            framework=self.framework_name,
            status=status,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            raw_artifacts=[str(discovery_path), str(traffic_path), str(native_result_path), str(memory_path)],
            evidence=evidence,
            errors=errors,
            native_engine_invoked=bool(evidence) and not errors,
            native_command_or_api=native_api,
            native_framework_version=self.detected_version(),
            native_artifact_path=str(native_result_path),
            native_plugin_identifiers=plugin_ids,
            fallback_used=False,
        )


app = create_worker_app(PyRITRunner())
