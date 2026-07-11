#!/usr/bin/env bash
set -euo pipefail

docker compose -f docker-compose.gpu.yml up -d ollama
echo "Ollama should be available at http://127.0.0.1:11434"

