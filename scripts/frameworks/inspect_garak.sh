#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)
SERVICE="${GARAK_SERVICE:-garak-worker}"

run_step() {
  local title="$1"
  shift
  echo
  echo "===== $title ====="
  "$@" || {
    status=$?
    echo "FAILED: $title exited with status $status"
    return "$status"
  }
}

"$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python - <<'PY'
import importlib
import inspect
import json
import pathlib
import sys

import garak
import garak.generators.target_proxy as target_proxy

payload = {
    "python": sys.version,
    "garak_version": getattr(garak, "__version__", None),
    "garak_file": getattr(garak, "__file__", None),
    "target_proxy_generator_file": target_proxy.__file__,
    "target_proxy_generator_class": "garak.generators.target_proxy.TargetProxyGenerator",
    "target_proxy_generator_signature": str(inspect.signature(target_proxy.TargetProxyGenerator.__init__)),
}
print(json.dumps(payload, indent=2, default=str))
PY

run_step "garak version" "$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python -m garak --version
run_step "target proxy generator plugin" "$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python -m garak --plugin_info generators.target_proxy.TargetProxyGenerator
run_step "selected probes" "$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python -m garak --list_probes -p "${GARAK_PROBES:-dan,promptinject,encoding}" --skip_unknown
run_step "detectors" "$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" exec -T "$SERVICE" python -m garak --list_detectors --skip_unknown
