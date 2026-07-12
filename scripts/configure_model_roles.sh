#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
MODEL_ROLE_PRESET="${MODEL_ROLE_PRESET:-recommended}"

RECOMMENDED_TARGET_MODEL="qwen3:4b"
RECOMMENDED_ATTACKER_MODEL="qwen3:14b"
RECOMMENDED_JUDGE_MODEL="gpt-oss:20b"
RECOMMENDED_PLANNER_MODEL="qwen3:8b"
RECOMMENDED_EMBEDDING_MODEL="nomic-embed-text"

if [[ ! -f "$ENV_FILE" ]]; then
  cp .env.example "$ENV_FILE"
fi

env_file_value() {
  local key="$1"
  grep -E "^${key}=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true
}

normalize_model() {
  local value="$1"
  value="${value#ollama/}"
  value="${value#ollama://}"
  echo "$value"
}

if [[ "$MODEL_ROLE_PRESET" == "custom" ]]; then
  TARGET_MODEL="$(normalize_model "${OLLAMA_TARGET_MODEL:-$(env_file_value OLLAMA_TARGET_MODEL)}")"
  ATTACKER_MODEL="$(normalize_model "${OLLAMA_ATTACKER_MODEL:-$(env_file_value OLLAMA_ATTACKER_MODEL)}")"
  JUDGE_MODEL="$(normalize_model "${OLLAMA_JUDGE_MODEL:-$(env_file_value OLLAMA_JUDGE_MODEL)}")"
  PLANNER_MODEL="$(normalize_model "${OLLAMA_PLANNER_MODEL:-$(env_file_value OLLAMA_PLANNER_MODEL)}")"
  EMBEDDING_MODEL="$(normalize_model "${OLLAMA_EMBEDDING_MODEL:-$(env_file_value OLLAMA_EMBEDDING_MODEL)}")"
  TARGET_MODEL="${TARGET_MODEL:-$RECOMMENDED_TARGET_MODEL}"
  ATTACKER_MODEL="${ATTACKER_MODEL:-$RECOMMENDED_ATTACKER_MODEL}"
  JUDGE_MODEL="${JUDGE_MODEL:-$RECOMMENDED_JUDGE_MODEL}"
  PLANNER_MODEL="${PLANNER_MODEL:-$RECOMMENDED_PLANNER_MODEL}"
  EMBEDDING_MODEL="${EMBEDDING_MODEL:-$RECOMMENDED_EMBEDDING_MODEL}"
else
  TARGET_MODEL="$RECOMMENDED_TARGET_MODEL"
  ATTACKER_MODEL="$RECOMMENDED_ATTACKER_MODEL"
  JUDGE_MODEL="$RECOMMENDED_JUDGE_MODEL"
  PLANNER_MODEL="$RECOMMENDED_PLANNER_MODEL"
  EMBEDDING_MODEL="$RECOMMENDED_EMBEDDING_MODEL"
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
echo "  preset:    $MODEL_ROLE_PRESET"
echo "  target:    $TARGET_MODEL"
echo "  attacker:  $ATTACKER_MODEL"
echo "  judge:     $JUDGE_MODEL"
echo "  planner:   $PLANNER_MODEL"
echo "  embedding: $EMBEDDING_MODEL"
