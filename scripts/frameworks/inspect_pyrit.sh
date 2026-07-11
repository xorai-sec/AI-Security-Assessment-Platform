#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)
SERVICE="${PYRIT_SERVICE:-pyrit-worker}"

"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python - <<'PY'
import importlib
import inspect
import json
import pkgutil
import sys

import pyrit

modules = sorted(
    module.name
    for module in pkgutil.walk_packages(pyrit.__path__, prefix="pyrit.")
    if any(key in module.name.lower() for key in ["target", "orchestrator", "attack", "score", "memory", "converter"])
)
symbols = {}
for module_name in modules[:200]:
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        symbols[module_name] = {"import_error": str(exc)}
        continue
    classes = {}
    for name, obj in inspect.getmembers(module, inspect.isclass):
        if obj.__module__ == module.__name__:
            try:
                classes[name] = str(inspect.signature(obj))
            except Exception:
                classes[name] = "signature-unavailable"
    if classes:
        symbols[module_name] = classes

print(json.dumps({
    "python": sys.version,
    "pyrit_version": getattr(pyrit, "__version__", "unknown"),
    "pyrit_file": getattr(pyrit, "__file__", None),
    "modules": modules,
    "classes": symbols,
}, indent=2, default=str))
PY

echo
echo "===== targeted native adapter APIs ====="
"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python - <<'PY'
import importlib
import inspect
import json

TARGETS = [
    "pyrit.prompt_target.common.prompt_chat_target.PromptChatTarget",
    "pyrit.prompt_target.text_target.TextTarget",
    "pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack",
    "pyrit.executor.attack.core.attack_executor.AttackExecutor",
    "pyrit.executor.attack.core.attack_parameters.AttackParameters",
    "pyrit.executor.attack.core.attack_config.AttackConverterConfig",
    "pyrit.executor.attack.core.attack_config.AttackScoringConfig",
    "pyrit.memory.sqlite_memory.SQLiteMemory",
    "pyrit.memory.central_memory.CentralMemory",
    "pyrit.prompt_converter.base64_converter.Base64Converter",
    "pyrit.prompt_converter.rot13_converter.ROT13Converter",
    "pyrit.score.scorer.Scorer",
    "pyrit.models.message.Message",
    "pyrit.models.message_piece.MessagePiece",
    "pyrit.models.attack_result.AttackResult",
    "pyrit.models.score.Score",
]

def describe(path):
    module_name, class_name = path.rsplit(".", 1)
    try:
        module = importlib.import_module(module_name)
        obj = getattr(module, class_name)
    except Exception as exc:
        return {"path": path, "import_error": str(exc)}
    methods = {}
    for name, member in inspect.getmembers(obj):
        if name.startswith("_") and name not in {"__init__"}:
            continue
        if inspect.isfunction(member) or inspect.ismethod(member) or inspect.iscoroutinefunction(member):
            try:
                methods[name] = str(inspect.signature(member))
            except Exception:
                methods[name] = "signature-unavailable"
    try:
        source_file = inspect.getsourcefile(obj)
    except Exception:
        source_file = None
    try:
        source = inspect.getsource(obj)[:4000]
    except Exception as exc:
        source = f"source unavailable: {exc}"
    return {
        "path": path,
        "module_file": source_file,
        "signature": str(inspect.signature(obj)) if callable(obj) else None,
        "mro": [item.__module__ + "." + item.__name__ for item in getattr(obj, "__mro__", [])],
        "methods": methods,
        "source_excerpt": source,
    }

print(json.dumps([describe(path) for path in TARGETS], indent=2, default=str))
PY
