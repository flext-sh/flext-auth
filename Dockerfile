FROM python:3.13-slim as builder

# Build arguments
ARG BUILD_ENV=production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.8.3

# Configure poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

# Copy poetry configuration
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry install --no-dev --no-root && rm -rf $POETRY_CACHE_DIR

# Production image
FROM python:3.13-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash flext

WORKDIR /app

# Copy virtual environment from builder stage
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY --chown=flext:flext src/ ./src/
COPY --chown=flext:flext scripts/ ./scripts/
COPY --chown=flext:flext .env.example ./

# Create logs directory
RUN mkdir -p /app/logs && chown flext:flext /app/logs

# Make sure we use venv
ENV PATH="/app/.venv/bin:$PATH"

# Health check
COPY --chown=flext:flext scripts/healthcheck.py ./healthcheck.py

# Switch to non-root user
USER flext

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python healthcheck.py

# Default command
CMD ["uvicorn", "flext_auth.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]