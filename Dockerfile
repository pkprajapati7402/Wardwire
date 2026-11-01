# Multi-stage hardened Dockerfile for Wardwire Backend Services
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir hatchling uv && \
    uv pip install --system --no-cache-dir .

FROM python:3.12-slim-bookworm AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Create non-root system user
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -m -s /bin/bash sentinel && \
    mkdir -p /app/data && \
    chown -R sentinel:sentinel /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY --chown=sentinel:sentinel src/ /app/src/
COPY --chown=sentinel:sentinel scripts/ /app/scripts/

USER sentinel

EXPOSE 8000 8001

CMD ["uvicorn", "sentinel.api.main:app", "--host", "0.0.0.0", "--port", "8001"]

