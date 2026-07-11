FROM python:3.12-slim
WORKDIR /worker
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential && rm -rf /var/lib/apt/lists/*
COPY workers/garak-worker/requirements.txt /worker/requirements.txt
RUN pip install --no-cache-dir -r /worker/requirements.txt
COPY workers/garak-worker/target_proxy_generator.py /worker/target_proxy_generator.py
RUN python - <<'PY'
from pathlib import Path
import shutil
import garak.generators

target = Path(garak.generators.__file__).parent / "target_proxy.py"
shutil.copyfile("/worker/target_proxy_generator.py", target)
print(f"Installed garak target proxy generator at {target}")
PY
COPY workers/common /worker/workers/common
COPY packages /worker/packages
COPY workers/garak-worker/app.py /worker/app.py
ENV PYTHONPATH=/worker
RUN useradd -m worker && mkdir -p /artifacts/garak && chown -R worker:worker /worker /artifacts
USER worker
EXPOSE 8092
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8092"]
