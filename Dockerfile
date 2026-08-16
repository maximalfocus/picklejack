# syntax=docker/dockerfile:1

FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=0 \
    PATH="/opt/venv/bin:$PATH"

# uv provides reproducible dependency installation from the committed lockfile.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# Install the project itself (README is referenced by the project metadata).
COPY README.md ./
COPY src ./src
COPY tests ./tests
COPY demo ./demo
RUN uv sync --frozen

# Drop to an unprivileged user for runtime.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "picklejack.main_secure:app", "--host", "0.0.0.0", "--port", "8000"]
