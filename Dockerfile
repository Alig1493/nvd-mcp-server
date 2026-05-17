FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ ./src/
RUN uv sync --frozen --no-dev

RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 8000

CMD [".venv/bin/nvd-mcp-server", "--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
