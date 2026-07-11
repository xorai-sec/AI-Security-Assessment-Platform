#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
OLLAMA_SERVICE="${OLLAMA_SERVICE:-ollama}"
TARGET_MODEL="${OLLAMA_TARGET_MODEL:-llama3.2:3b}"
ATTACKER_MODEL="${OLLAMA_ATTACKER_MODEL:-llama3.1:8b}"
JUDGE_MODEL="${OLLAMA_JUDGE_MODEL:-llama3.1:8b}"

compose() {
  "$DOCKER_BIN" compose -f docker-compose.yml -f docker-compose.frameworks.yml "$@"
}

pull_model() {
  local model="$1"
  if [[ -z "$model" || "$model" == "unknown" ]]; then
    return 0
  fi
  echo "Pulling Ollama model: $model"
  compose exec "$OLLAMA_SERVICE" ollama pull "$model"
}

if ! compose ps "$OLLAMA_SERVICE" >/dev/null 2>&1; then
  echo "Ollama service is not available in the compose project."
  echo "Start the stack first, then run this script again."
  exit 1
fi

echo "Configured model roles:"
echo "  target:   $TARGET_MODEL"
echo "  attacker: $ATTACKER_MODEL"
echo "  judge:    $JUDGE_MODEL"

if [[ "$TARGET_MODEL" == "$ATTACKER_MODEL" || "$TARGET_MODEL" == "$JUDGE_MODEL" || "$ATTACKER_MODEL" == "$JUDGE_MODEL" ]]; then
  echo "Warning: at least two model roles share the same model. This is allowed for lab work, but judge results can be biased."
fi

pull_model "$TARGET_MODEL"
pull_model "$ATTACKER_MODEL"
pull_model "$JUDGE_MODEL"

echo "Available Ollama models:"
compose exec "$OLLAMA_SERVICE" ollama list
