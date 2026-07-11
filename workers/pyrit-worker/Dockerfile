FROM python:3.12-slim
WORKDIR /worker
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential && rm -rf /var/lib/apt/lists/*
COPY workers/pyrit-worker/requirements.txt /worker/requirements.txt
RUN pip install --no-cache-dir -r /worker/requirements.txt
COPY workers/common /worker/workers/common
COPY workers/pyrit-worker/app.py /worker/app.py
ENV PYTHONPATH=/worker
RUN useradd -m worker && mkdir -p /artifacts/pyrit && chown -R worker:worker /worker /artifacts
USER worker
EXPOSE 8093
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8093"]
