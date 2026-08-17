# KavachX backend.
#
# Two stages: dependencies resolved with uv against a locked set, then a slim runtime that runs
# as a non-root user. The entrypoint applies migrations and seeds the demo tenant before serving,
# so `docker compose up` reaches a usable console with no extra steps.

FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.9.5 /uv /uvx /usr/local/bin/

WORKDIR /app
COPY pyproject.toml ./
COPY uv.lock* ./

# Dependencies only, so this layer caches independently of application code.
RUN uv venv /opt/venv \
 && if [ -f uv.lock ]; then \
        uv sync --frozen --no-install-project --no-dev; \
    else \
        uv sync --no-install-project --no-dev; \
    fi


# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    VIRTUAL_ENV=/opt/venv

# git is present for future GitHub ingestion paths; it is never invoked inside the sandbox.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1001 kavachx \
 && useradd --system --uid 1001 --gid kavachx --create-home kavachx

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=kavachx:kavachx . /app

RUN mkdir -p /workspaces /app/logs \
 && chown -R kavachx:kavachx /workspaces /app/logs

USER kavachx

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=6 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
