#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
OLLAMA_SERVICE="${OLLAMA_SERVICE:-ollama}"
ENV_FILE="${ENV_FILE:-.env}"
OLLAMA_CONTAINER="${OLLAMA_CONTAINER:-}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)

if [[ -f "$ENV_FILE" && "${SKIP_ENV_FILE:-false}" != "true" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

normalize_model() {
  local value="$1"
  value="${value#ollama/}"
  value="${value#ollama://}"
  echo "$value"
}

TARGET_MODEL="$(normalize_model "${OLLAMA_TARGET_MODEL:-qwen3:4b}")"
ATTACKER_MODEL="$(normalize_model "${OLLAMA_ATTACKER_MODEL:-qwen3:14b}")"
JUDGE_MODEL="$(normalize_model "${OLLAMA_JUDGE_MODEL:-gpt-oss:20b}")"
PLANNER_MODEL="$(normalize_model "${OLLAMA_PLANNER_MODEL:-qwen3:8b}")"
EMBEDDING_MODEL="$(normalize_model "${OLLAMA_EMBEDDING_MODEL:-nomic-embed-text}")"

if [[ -f docker-compose.gpu.yml ]]; then
  COMPOSE_FILES+=(-f docker-compose.gpu.yml)
fi

compose() {
  docker_cmd compose "${COMPOSE_FILES[@]}" "$@"
}

docker_cmd() {
  local docker_parts=()
  read -r -a docker_parts <<< "$DOCKER_BIN"
  "${docker_parts[@]}" "$@"
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
  docker_cmd ps --format '{{.Names}}' | grep -E '(^|-)ollama(-|$)' | head -1
}

ollama_exec() {
  local container="$1"
  shift
  docker_cmd exec "$container" "$@"
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
echo "  target:    $TARGET_MODEL"
echo "  attacker:  $ATTACKER_MODEL"
echo "  judge:     $JUDGE_MODEL"
echo "  planner:   $PLANNER_MODEL"
echo "  embedding: $EMBEDDING_MODEL"

if [[ "$TARGET_MODEL" == "$ATTACKER_MODEL" || "$TARGET_MODEL" == "$JUDGE_MODEL" || "$TARGET_MODEL" == "$PLANNER_MODEL" || "$ATTACKER_MODEL" == "$JUDGE_MODEL" || "$ATTACKER_MODEL" == "$PLANNER_MODEL" || "$JUDGE_MODEL" == "$PLANNER_MODEL" ]]; then
  echo "Warning: at least two model roles share the same model. This is allowed for lab work, but judge results can be biased."
fi

echo "Using Ollama container: $CONTAINER"

pull_model "$CONTAINER" "$TARGET_MODEL"
pull_model "$CONTAINER" "$ATTACKER_MODEL"
pull_model "$CONTAINER" "$JUDGE_MODEL"
pull_model "$CONTAINER" "$PLANNER_MODEL"
pull_model "$CONTAINER" "$EMBEDDING_MODEL"

echo "Available Ollama models:"
ollama_exec "$CONTAINER" ollama list
