FROM python:3.12-slim
WORKDIR /worker
COPY workers/native-worker/requirements.txt /worker/requirements.txt
RUN pip install --no-cache-dir -r /worker/requirements.txt
COPY workers/common /worker/workers/common
COPY packages /worker/packages
COPY workers/native-worker/app.py /worker/app.py
ENV PYTHONPATH=/worker
RUN useradd -m worker && mkdir -p /artifacts/native && chown -R worker:worker /worker /artifacts
USER worker
EXPOSE 8091
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8091"]
