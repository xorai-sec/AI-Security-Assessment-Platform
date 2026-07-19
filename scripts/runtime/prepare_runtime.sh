#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKER_UID="${WORKER_UID:-1000}"
WORKER_GID="${WORKER_GID:-1000}"

mkdir -p \
  "$ROOT/data/framework-artifacts/native" \
  "$ROOT/data/framework-artifacts/garak" \
  "$ROOT/data/framework-artifacts/pyrit" \
  "$ROOT/data/framework-artifacts/promptfoo" \
  "$ROOT/data/framework-results" \
  "$ROOT/data/evidence" \
  "$ROOT/data/reports"

chmod 775 \
  "$ROOT/data/framework-artifacts/native" \
  "$ROOT/data/framework-artifacts/garak" \
  "$ROOT/data/framework-artifacts/pyrit" \
  "$ROOT/data/framework-artifacts/promptfoo"

if command -v chown >/dev/null 2>&1; then
  if [ "$(id -u)" = "0" ]; then
    chown "$WORKER_UID:$WORKER_GID" \
      "$ROOT/data/framework-artifacts/native" \
      "$ROOT/data/framework-artifacts/garak" \
      "$ROOT/data/framework-artifacts/pyrit" \
      "$ROOT/data/framework-artifacts/promptfoo"
  elif [ "${ALLOW_SUDO:-0}" = "1" ] && command -v sudo >/dev/null 2>&1; then
    sudo chown "$WORKER_UID:$WORKER_GID" \
      "$ROOT/data/framework-artifacts/native" \
      "$ROOT/data/framework-artifacts/garak" \
      "$ROOT/data/framework-artifacts/pyrit" \
      "$ROOT/data/framework-artifacts/promptfoo"
  fi
fi

echo "Runtime directories are ready for worker UID:GID ${WORKER_UID}:${WORKER_GID}."
