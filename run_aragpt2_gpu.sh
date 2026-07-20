#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"
ENV_NAME="jais310"
PORT="8003"
export HSA_OVERRIDE_GFX_VERSION="${HSA_OVERRIDE_GFX_VERSION:-11.0.0}"

command -v conda >/dev/null || { echo "ERROR: conda is not on PATH" >&2; exit 1; }
PY=(conda run --no-capture-output -n "$ENV_NAME" python)

echo "== Python environment =="
"${PY[@]}" -c 'import sys; print(sys.executable); print(sys.version)'

if ! "${PY[@]}" -c 'import torch; assert torch.version.hip, torch.__version__; assert torch.cuda.is_available()' >/dev/null 2>&1; then
  echo "Installing ROCm PyTorch into Conda environment $ENV_NAME ..."
  "${PY[@]}" -m pip install --upgrade pip numpy
  "${PY[@]}" -m pip uninstall -y torch torchvision torchaudio >/dev/null 2>&1 || true
  "${PY[@]}" -m pip install torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/rocm6.2
fi

"${PY[@]}" -m pip install \
  'transformers==4.28.0' 'tokenizers==0.13.3' accelerate fastapi 'uvicorn[standard]' \
  sentencepiece safetensors huggingface_hub

echo "== GPU check =="
env HSA_OVERRIDE_GFX_VERSION="$HSA_OVERRIDE_GFX_VERSION" "${PY[@]}" -c \
  'import torch; print("torch:", torch.__version__); print("hip:", torch.version.hip); print("gpu:", torch.cuda.is_available()); print("device:", torch.cuda.get_device_name(0) if torch.cuda.is_available() else "NONE"); assert torch.cuda.is_available()'

pkill -f 'serve_aragpt2:app' 2>/dev/null || true
echo "== Starting AraGPT2 on port $PORT =="
nohup env HSA_OVERRIDE_GFX_VERSION="$HSA_OVERRIDE_GFX_VERSION" \
  conda run --no-capture-output -n "$ENV_NAME" python -u -m uvicorn serve_aragpt2:app \
  --host 0.0.0.0 --port "$PORT" > aragpt2.log 2>&1 &
echo $! > aragpt2.pid

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/health"; then
    echo
    exit 0
  fi
  sleep 2
done

echo "ERROR: server did not become healthy; last log output:" >&2
tail -100 aragpt2.log >&2
exit 1
