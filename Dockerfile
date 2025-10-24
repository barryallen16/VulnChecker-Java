FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-headless \
    semgrep \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

COPY triage/ ./triage/
COPY training/ ./training/

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["triagemate"]
