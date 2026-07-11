#!/usr/bin/env bash
set -euo pipefail

MODEL="${MODEL:-Qwen/Qwen2.5-7B-Instruct}"
docker run --rm --gpus all -p 8001:8000 \
  -e HUGGING_FACE_HUB_TOKEN="${HUGGING_FACE_HUB_TOKEN:-}" \
  vllm/vllm-openai:latest \
  --model "$MODEL"

