#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
OLLAMA_SERVICE="${OLLAMA_SERVICE:-ollama}"
TARGET_MODEL="${OLLAMA_TARGET_MODEL:-llama3.2:3b}"
ATTACKER_MODEL="${OLLAMA_ATTACKER_MODEL:-llama3.1:8b}"
JUDGE_MODEL="${OLLAMA_JUDGE_MODEL:-llama3.1:8b}"
OLLAMA_CONTAINER="${OLLAMA_CONTAINER:-}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)

if [[ -f docker-compose.gpu.yml ]]; then
  COMPOSE_FILES+=(-f docker-compose.gpu.yml)
fi

compose() {
  "$DOCKER_BIN" compose "${COMPOSE_FILES[@]}" "$@"
}

detect_ollama_container() {
  if [[ -n "$OLLAMA_CONTAINER" ]]; then
    echo "$OLLAMA_CONTAINER"
    return 0
  fi
  local compose_container
  compose_container="$(compose ps -q "$OLLAMA_SERVICE" 2>/dev/null || true)"
  if [[ -n "$compose_container" ]]; then
    echo "$compose_container"
    return 0
  fi
  "$DOCKER_BIN" ps --format '{{.Names}}' | grep -E '(^|-)ollama(-|$)' | head -1
}

ollama_exec() {
  local container="$1"
  shift
  "$DOCKER_BIN" exec "$container" "$@"
}

pull_model() {
  local container="$1"
  local model="$2"
  if [[ -z "$model" || "$model" == "unknown" ]]; then
    return 0
  fi
  echo "Pulling Ollama model: $model"
  ollama_exec "$container" ollama pull "$model"
}

CONTAINER="$(detect_ollama_container || true)"

if [[ -z "$CONTAINER" ]]; then
  echo "Ollama service is not available in the compose project."
  echo "Start it with: docker compose -f docker-compose.yml -f docker-compose.frameworks.yml -f docker-compose.gpu.yml up -d ollama"
  echo "Or set OLLAMA_CONTAINER=<container-name> if Ollama is already running elsewhere."
  exit 1
fi

echo "Configured model roles:"
echo "  target:   $TARGET_MODEL"
echo "  attacker: $ATTACKER_MODEL"
echo "  judge:    $JUDGE_MODEL"

if [[ "$TARGET_MODEL" == "$ATTACKER_MODEL" || "$TARGET_MODEL" == "$JUDGE_MODEL" || "$ATTACKER_MODEL" == "$JUDGE_MODEL" ]]; then
  echo "Warning: at least two model roles share the same model. This is allowed for lab work, but judge results can be biased."
fi

echo "Using Ollama container: $CONTAINER"

pull_model "$CONTAINER" "$TARGET_MODEL"
pull_model "$CONTAINER" "$ATTACKER_MODEL"
pull_model "$CONTAINER" "$JUDGE_MODEL"

echo "Available Ollama models:"
ollama_exec "$CONTAINER" ollama list
