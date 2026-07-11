FROM python:3.12-slim

WORKDIR /app
COPY apps/api/requirements.txt /app/apps/api/requirements.txt
RUN pip install --no-cache-dir -r /app/apps/api/requirements.txt
COPY packages /app/packages
COPY apps/api/app /app/apps/api/app
ENV PYTHONPATH=/app
RUN useradd -m appuser && mkdir -p /app/data/evidence /app/data/reports && chown -R appuser:appuser /app
USER appuser
EXPOSE 8080
CMD ["uvicorn", "apps.api.app.main:app", "--host", "0.0.0.0", "--port", "8080"]

