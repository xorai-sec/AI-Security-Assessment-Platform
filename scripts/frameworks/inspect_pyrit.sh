#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)
SERVICE="${PYRIT_SERVICE:-pyrit-worker}"

"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec "$SERVICE" python - <<'PY'
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
