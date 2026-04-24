# ─── AttackTrace Backend Dockerfile ──────────────────────────────────────────────────
#
# Multi-stage build to keep the final image lean:
#   builder  — compile C extensions, install Python deps into a venv
#   runtime  — copy only the venv + app, run as non-root
#
# Build context: repo root (.)
# Dockerfile:    platform/backend/Dockerfile
#
# The attacktrace/ CLI package at the repo root is copied into the image
# and installed with pip, then removed to keep the layer clean.

# ═══════════════════════════════════════════════════════════════
# Stage 1 — builder
# ═══════════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

# System dependencies needed to compile psycopg2, cryptography, lxml, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create an isolated venv so we can copy it cleanly to the runtime stage
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip/wheel first for reliable builds
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python dependencies
COPY platform/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ═══════════════════════════════════════════════════════════════
# Stage 2 — runtime
# ═══════════════════════════════════════════════════════════════
FROM python:3.11-slim AS runtime

# Runtime system deps: libpq for psycopg2, curl for healthchecks,
# and Playwright browser dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    # Playwright / Chromium system dependencies
    libnss3 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libgbm1 \
    libasound2 \
    libxrandr2 \
    libxdamage1 \
    libxfixes3 \
    libxcomposite1 \
    libxext6 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxss1 \
    libxtst6 \
    fonts-liberation \
    libappindicator3-1 \
    xdg-utils \
    ca-certificates \
    nmap \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Grant nmap raw socket capabilities so it can run ACK/SYN/fragmented scans
# without running as root. The || true prevents build failure on systems where
# setcap is unavailable (some CI environments).
RUN setcap cap_net_raw,cap_net_admin=eip $(which nmap) || true

# Copy the compiled venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Playwright and download Chromium browser binary.
# We install only chromium (not firefox/webkit) to keep the image size down.
# Scans use Chromium for screenshot capture.
RUN /opt/venv/bin/playwright install chromium --with-deps

# Create a non-root user to run the service
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home --shell /bin/bash appuser

# Application directory
WORKDIR /app

# Copy the AttackTrace CLI package source so it's available for `pip install -e .`
# The build context must include the attacktrace/ directory (build from repo root).
COPY --chown=appuser:appgroup attacktrace/ /app/attacktrace/
RUN pip install --no-cache-dir /app/attacktrace/ && rm -rf /app/attacktrace/

# Copy application source
COPY --chown=appuser:appgroup platform/backend/app/ /app/app/

# Alembic config lives at /app so `alembic upgrade head` works from /app
COPY --chown=appuser:appgroup platform/backend/alembic.ini /app/alembic.ini
COPY --chown=appuser:appgroup platform/backend/alembic/ /app/alembic/

# Writable directory for scan workspace
RUN mkdir -p /tmp/attacktrace_scans && chown appuser:appgroup /tmp/attacktrace_scans

USER appuser

# Expose the API port
EXPOSE 8000

# Health check — avoids the container being marked healthy before uvicorn is up
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command — uvicorn with a small number of workers for dev.
# In production override this with --workers $(nproc) or use gunicorn.
# Reload is OFF in the image; dev hot-reload comes from the volume mount
# + compose override: command: uvicorn app.main:app --reload --host 0.0.0.0
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
