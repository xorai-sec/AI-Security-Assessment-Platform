#!/usr/bin/env bash
set -euo pipefail

MODEL="${MODEL:-llama3.2:3b}"
if ! command -v ollama >/dev/null 2>&1; then
  echo "Install Ollama first or run scripts/gpu/start_ollama.sh"
  exit 1
fi
ollama pull "$MODEL"

