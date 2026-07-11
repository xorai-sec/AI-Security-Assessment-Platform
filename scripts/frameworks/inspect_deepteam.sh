#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)
SERVICE="${DEEPTEAM_SERVICE:-deepteam-worker}"

"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec "$SERVICE" python - <<'PY'
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
