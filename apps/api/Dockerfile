FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY apps/api /app/apps/api
COPY legacy /app/legacy
WORKDIR /app/apps/api
RUN pip install --no-cache-dir -e .
# Legacy 10-stage CLI is exposed in the registry as oneforall_sNN_*; install it
# so `python -m oneforall ...` works inside the API and worker containers.
RUN pip install --no-cache-dir -e /app/legacy

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
