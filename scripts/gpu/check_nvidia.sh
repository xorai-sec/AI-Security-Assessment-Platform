#!/usr/bin/env bash
set -euo pipefail

if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi
else
  echo "nvidia-smi not found. This machine may be AMD/CPU-only. CPU fallback is supported for the basic demo."
fi

