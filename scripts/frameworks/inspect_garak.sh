#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)
SERVICE="${GARAK_SERVICE:-garak-worker}"

"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec "$SERVICE" python - <<'PY'
import importlib
import inspect
import json
import pathlib
import sys

import garak
import garak._plugins as plugins
import garak.generators.target_proxy as target_proxy

payload = {
    "python": sys.version,
    "garak_version": getattr(garak, "__version__", None),
    "garak_file": getattr(garak, "__file__", None),
    "target_proxy_generator_file": target_proxy.__file__,
    "target_proxy_generator_class": "garak.generators.target_proxy.TargetProxyGenerator",
    "target_proxy_generator_signature": str(inspect.signature(target_proxy.TargetProxyGenerator.__init__)),
    "generators": [name for name, active in plugins.enumerate_plugins("generators") if "target_proxy" in name or name in {"rest.RestGenerator"}],
    "sample_probes": plugins.enumerate_plugins("probes")[:50],
    "sample_detectors": plugins.enumerate_plugins("detectors")[:50],
}
print(json.dumps(payload, indent=2, default=str))
PY

"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec "$SERVICE" python -m garak --version
"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec "$SERVICE" python -m garak --plugin_info generators.target_proxy.TargetProxyGenerator
"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec "$SERVICE" python -m garak --list_probes -p "${GARAK_PROBES:-dan,promptinject,encoding}" --skip_unknown
"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec "$SERVICE" python -m garak --list_detectors --skip_unknown
