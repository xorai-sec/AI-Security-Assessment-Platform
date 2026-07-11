# GPU Deployment

The core demo runs without GPU.

For NVIDIA systems:

```bash
bash scripts/gpu/check_nvidia.sh
bash scripts/gpu/check_docker_gpu.sh
bash scripts/gpu/start_ollama.sh
MODEL=llama3.2:3b bash scripts/gpu/pull_demo_model.sh
```

For the current AMD/CPU lab machine, use CPU fallback. Do not install NVIDIA-only
components unless the machine actually has an NVIDIA GPU.

Recommended default model for demos:

```text
llama3.2:3b
```

Recommended stronger model for larger NVIDIA GPUs:

```text
Qwen/Qwen2.5-7B-Instruct
```

