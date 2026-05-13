# ─── AttackTrace Backend Dockerfile ───────────────────────────────────────────
#
# Three-stage build:
#   go-builder   — compiles all Go-based security tools (nuclei, ffuf, etc.)
#   py-builder   — installs Python deps into an isolated venv
#   runtime      — lean final image with venv + Go binaries + system tools
#
# Build context: repo root (.)
# Dockerfile:    platform/backend/Dockerfile

# ═══════════════════════════════════════════════════════════════
# Stage 0 — Go tools builder
# Compiles all Go-based security tools as static binaries.
# The Go toolchain is NOT copied to the runtime image.
# ═══════════════════════════════════════════════════════════════
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS go-builder

# Target the runtime platform so the binaries run in the final image
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0

RUN apk add --no-cache git ca-certificates

# Install Go-based security tools in a single layer.
# Pinned to @latest for the most recent stable releases.
# Use `go install <pkg>@<version>` here if you need reproducible builds.
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest                          && \
    go install github.com/sensepost/gowitness@latest                    && \
    go install github.com/lc/gau/v2/cmd/gau@latest                     && \
    go install github.com/tomnomnom/waybackurls@latest                  && \
    go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest

# ═══════════════════════════════════════════════════════════════
# Stage 1 — Python builder
# Compiles C extensions and installs Python deps into a venv.
# ═══════════════════════════════════════════════════════════════
FROM python:3.11-slim AS py-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY platform/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# checkov (IaC scanner) — pip-only tool, install in the venv
RUN pip install --no-cache-dir checkov

# ═══════════════════════════════════════════════════════════════
# Stage 2 — Runtime
# Lean final image: venv + Go binaries + system security tools.
# ═══════════════════════════════════════════════════════════════
FROM python:3.11-slim AS runtime

# ── System packages ──────────────────────────────────────────
# libpq5          — PostgreSQL client (asyncpg/psycopg2)
# curl            — healthcheck + trivy install script
# nmap + libcap   — port scanning with raw socket support
# Playwright deps — Chromium headless browser (screenshots)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    # nmap
    nmap \
    libcap2-bin \
    # Playwright / Chromium dependencies
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
    && rm -rf /var/lib/apt/lists/*

# Grant nmap raw socket capabilities (ACK/SYN scans without root)
RUN setcap cap_net_raw,cap_net_admin=eip "$(which nmap)" || true

# ── Go security tools ─────────────────────────────────────────
COPY --from=go-builder /go/bin/nuclei      /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/ffuf        /usr/local/bin/ffuf
COPY --from=go-builder /go/bin/gowitness   /usr/local/bin/gowitness
COPY --from=go-builder /go/bin/gau         /usr/local/bin/gau
COPY --from=go-builder /go/bin/waybackurls /usr/local/bin/waybackurls
COPY --from=go-builder /go/bin/cloudlist   /usr/local/bin/cloudlist

# ── Trivy (container + IaC vulnerability scanner) ────────────
# Official install script handles amd64 / arm64 automatically.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Python venv ───────────────────────────────────────────────
COPY --from=py-builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# ── Playwright Chromium browser binary ───────────────────────
RUN /opt/venv/bin/playwright install chromium --with-deps

# ── Non-root user ────────────────────────────────────────────
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home --shell /bin/bash appuser

WORKDIR /app

# ── AttackTrace CLI + AttackMapper packages ───────────────────
COPY --chown=appuser:appgroup attacktrace/        /app/attacktrace/
COPY --chown=appuser:appgroup tools/attackmapper/ /app/tools/attackmapper/
RUN pip install --no-cache-dir /app/attacktrace/ /app/tools/attackmapper/ && \
    rm -rf /app/attacktrace/ /app/tools/attackmapper/

# ── Application source + Alembic migrations ───────────────────
COPY --chown=appuser:appgroup platform/backend/app/     /app/app/
COPY --chown=appuser:appgroup platform/backend/alembic.ini /app/alembic.ini
COPY --chown=appuser:appgroup platform/backend/alembic/ /app/alembic/

# ── Writable runtime directories ─────────────────────────────
# Nuclei templates — downloaded on first run, persisted via volume
RUN mkdir -p /tmp/attacktrace_scans /opt/nuclei-templates && \
    chown appuser:appgroup /tmp/attacktrace_scans /opt/nuclei-templates

# Tell nuclei where to store templates
ENV NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production: 2 workers. Override via compose for dev (--reload) or scale-out (--workers N).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
