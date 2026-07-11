FROM python:3.12-slim

WORKDIR /app
COPY apps/enterprise-assist/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY apps/enterprise-assist/app /app/app
RUN useradd -m appuser
USER appuser
EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]

