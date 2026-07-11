#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)
SERVICE="${DEEPTEAM_SERVICE:-deepteam-worker}"

"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python - <<'PY'
import importlib
import inspect
import json
import pkgutil
import sys

import deepteam

modules = sorted(
    module.name
    for module in pkgutil.walk_packages(deepteam.__path__, prefix="deepteam.")
    if any(key in module.name.lower() for key in ["vulner", "attack", "scan", "red", "eval", "target"])
)
symbols = {}
for module_name in modules[:200]:
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        symbols[module_name] = {"import_error": str(exc)}
        continue
    classes = {}
    functions = []
    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and obj.__module__ == module.__name__:
            try:
                classes[name] = str(inspect.signature(obj))
            except Exception:
                classes[name] = "signature-unavailable"
        elif inspect.isfunction(obj) and obj.__module__ == module.__name__:
            functions.append(name)
    if classes or functions:
        symbols[module_name] = {"classes": classes, "functions": functions}

print(json.dumps({
    "python": sys.version,
    "deepteam_version": getattr(deepteam, "__version__", "unknown"),
    "deepteam_file": getattr(deepteam, "__file__", None),
    "modules": modules,
    "symbols": symbols,
}, indent=2, default=str))
PY

echo
echo "===== targeted native adapter APIs ====="
"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python - <<'PY'
import importlib
import inspect
import json

TARGETS = [
    "deepteam.red_team.red_team",
    "deepteam.red_teamer.red_teamer.RedTeamer",
    "deepteam.red_teamer.utils.wrap_model_callback",
    "deepteam.red_teamer.utils.resolve_model_callback",
    "deepteam.attacks.attack_engine.attack_engine.AttackEngine",
    "deepteam.vulnerabilities.prompt_leakage.prompt_leakage.PromptLeakage",
    "deepteam.vulnerabilities.pii_leakage.pii_leakage.PIILeakage",
    "deepteam.vulnerabilities.rbac.rbac.RBAC",
    "deepteam.vulnerabilities.bfla.bfla.BFLA",
    "deepteam.vulnerabilities.cross_context_retrieval.cross_context_retrieval.CrossContextRetrieval",
    "deepteam.test_case.test_case.RTTurn",
    "deepteam.test_case.test_case.RTTestCase",
    "deepteam.attacks.base_attack.BaseAttack",
    "deepteam.attacks.single_turn.jailbreaking.linear_jailbreaking.LinearJailbreaking",
    "deepteam.attacks.multi_turn.roleplay.roleplay.Roleplay",
]

def describe(path):
    module_name, name = path.rsplit(".", 1)
    try:
        module = importlib.import_module(module_name)
        obj = getattr(module, name)
    except Exception as exc:
        return {"path": path, "import_error": str(exc)}
    methods = {}
    for method_name, member in inspect.getmembers(obj):
        if method_name.startswith("_") and method_name not in {"__init__"}:
            continue
        if inspect.isfunction(member) or inspect.ismethod(member) or inspect.iscoroutinefunction(member):
            try:
                methods[method_name] = str(inspect.signature(member))
            except Exception:
                methods[method_name] = "signature-unavailable"
    try:
        signature = str(inspect.signature(obj))
    except Exception:
        signature = "signature-unavailable"
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
        "signature": signature,
        "mro": [item.__module__ + "." + item.__name__ for item in getattr(obj, "__mro__", [])],
        "methods": methods,
        "source_excerpt": source,
    }

print(json.dumps([describe(path) for path in TARGETS], indent=2, default=str))
PY
