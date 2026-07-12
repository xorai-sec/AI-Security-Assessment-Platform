#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"

TARGET_MODEL="${OLLAMA_TARGET_MODEL:-qwen3:4b}"
ATTACKER_MODEL="${OLLAMA_ATTACKER_MODEL:-qwen3:14b}"
JUDGE_MODEL="${OLLAMA_JUDGE_MODEL:-gpt-oss:20b}"
PLANNER_MODEL="${OLLAMA_PLANNER_MODEL:-qwen3:8b}"
EMBEDDING_MODEL="${OLLAMA_EMBEDDING_MODEL:-nomic-embed-text}"

if [[ ! -f "$ENV_FILE" ]]; then
  cp .env.example "$ENV_FILE"
fi

set_env() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

set_env MODEL_NAME "$TARGET_MODEL"
set_env OLLAMA_TARGET_MODEL "$TARGET_MODEL"
set_env OLLAMA_ATTACKER_MODEL "$ATTACKER_MODEL"
set_env OLLAMA_JUDGE_MODEL "$JUDGE_MODEL"
set_env OLLAMA_PLANNER_MODEL "$PLANNER_MODEL"
set_env OLLAMA_EMBEDDING_MODEL "$EMBEDDING_MODEL"
set_env ADAPTIVE_PLANNER_LLM_ENABLED true
set_env ALLOW_SAME_MODEL_EVAL false

echo "Configured model roles in $ENV_FILE:"
echo "  target:    $TARGET_MODEL"
echo "  attacker:  $ATTACKER_MODEL"
echo "  judge:     $JUDGE_MODEL"
echo "  planner:   $PLANNER_MODEL"
echo "  embedding: $EMBEDDING_MODEL"
