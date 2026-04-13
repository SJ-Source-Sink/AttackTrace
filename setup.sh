#!/usr/bin/env bash
# ─── AttackTrace — One-Command Setup ─────────────────────────────────────────
#
# Clones? Just run:
#   chmod +x setup.sh && ./setup.sh
#
# Or via Make:
#   make setup
#
# What this does:
#   1. Checks Docker + Docker Compose are available
#   2. Generates a .env with random secrets (skips if .env already exists)
#   3. Builds all Docker images
#   4. Starts Postgres + Redis, waits until healthy
#   5. Runs database migrations (Alembic)
#   6. Seeds the first admin user + default org + open invite code
#   7. Starts remaining services (backend, worker, frontend)
#   8. Prints login credentials and URLs
#
# Re-running is safe — migrations and seed are idempotent.

set -euo pipefail

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()   { echo -e "${CYAN}  ▸${NC} $*"; }
ok()     { echo -e "${GREEN}  ✓${NC} $*"; }
warn()   { echo -e "${YELLOW}  !${NC} $*"; }
err()    { echo -e "${RED}  ✗${NC} $*" >&2; }
header() { echo -e "\n${BOLD}${CYAN}── $* ──${NC}"; }
die()    { err "$*"; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ─── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║          AttackTrace — Setup                       ║${NC}"
echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Prerequisite checks ───────────────────────────────────────────────────
header "Checking prerequisites"

check_cmd() {
  local cmd="$1" hint="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    ok "$cmd found"
  else
    die "$cmd not found. $hint"
  fi
}

check_cmd docker  "Install Docker Desktop from https://docs.docker.com/get-docker/"

# Docker Compose v2 (plugin) or v1 (standalone)
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
  ok "docker compose (v2 plugin) found"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
  ok "docker-compose (v1) found"
else
  die "Docker Compose not found. Install Docker Desktop which includes Compose."
fi

# Make sure Docker daemon is running
if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running. Start Docker Desktop and try again."
fi
ok "Docker daemon is running"

# ─── 2. Generate .env ─────────────────────────────────────────────────────────
header "Environment configuration"

if [ -f ".env" ]; then
  ok ".env already exists — using existing file"
  warn "Delete .env and re-run setup.sh to regenerate secrets."
else
  if [ ! -f ".env.example" ]; then
    die ".env.example not found. Make sure you cloned the full repository."
  fi

  info "Generating .env from .env.example with random secrets…"
  cp .env.example .env

  # Generate a cryptographically random SECRET_KEY (64 hex chars)
  if command -v openssl >/dev/null 2>&1; then
    SECRET_KEY=$(openssl rand -hex 32)
    KMS_KEY=$(openssl rand -base64 32)
  else
    # Fallback: use /dev/urandom
    SECRET_KEY=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
    KMS_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  fi

  # Replace placeholder values in .env
  sed -i.bak \
    -e "s|change-me-in-production-use-openssl-rand-hex-32|${SECRET_KEY}|g" \
    -e "s|change-me-32-bytes-base64-encoded=|${KMS_KEY}|g" \
    .env && rm -f .env.bak

  ok ".env created with fresh random secrets"
fi

# Read credentials from .env for the summary at the end
ADMIN_EMAIL=$(grep -E '^FIRST_SUPERUSER_EMAIL=' .env | cut -d= -f2 | tr -d '"' || echo "admin")
ADMIN_PASS=$(grep -E '^FIRST_SUPERUSER_PASSWORD=' .env | cut -d= -f2 | tr -d '"' || echo "Ihate13\$")

# ─── 3. Build Docker images ───────────────────────────────────────────────────
header "Building Docker images"
info "This may take 3–5 minutes on the first run (downloading base images + compiling deps)…"
$DC build --quiet
ok "Images built"

# ─── 4. Start data layer (Postgres + Redis) ───────────────────────────────────
header "Starting data services"
info "Starting Postgres and Redis…"
$DC up -d postgres redis

# Wait for postgres to be healthy
info "Waiting for Postgres to be ready…"
RETRIES=30
until $DC exec -T postgres pg_isready -U attacktrace -d attacktrace >/dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  if [ $RETRIES -le 0 ]; then
    err "Postgres did not become ready in time."
    $DC logs postgres | tail -20
    exit 1
  fi
  sleep 2
done
ok "Postgres is ready"

# Wait for redis
info "Waiting for Redis to be ready…"
RETRIES=15
until $DC exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do
  RETRIES=$((RETRIES - 1))
  if [ $RETRIES -le 0 ]; then
    err "Redis did not become ready in time."
    exit 1
  fi
  sleep 2
done
ok "Redis is ready"

# ─── 5. Run Alembic migrations ────────────────────────────────────────────────
header "Running database migrations"
info "Starting backend container for migrations…"
$DC up -d backend

# Wait for backend to be healthy before running alembic
RETRIES=30
until $DC exec -T backend curl -sf http://localhost:8000/health >/dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  if [ $RETRIES -le 0 ]; then
    warn "Backend health check timed out — attempting migrations anyway…"
    break
  fi
  sleep 3
done

info "Running Alembic upgrade head…"
$DC exec -T backend alembic upgrade head
ok "Migrations complete"

# ─── 6. Seed initial data ─────────────────────────────────────────────────────
header "Seeding initial data"
info "Creating admin user and default organisation…"
$DC exec -T backend python -m app.initial_data
ok "Seed complete"

# ─── 7. Start all remaining services ─────────────────────────────────────────
header "Starting all services"
info "Starting worker, worker-beat, and frontend…"
$DC up -d
ok "All services started"

# Give frontend a moment to initialise
sleep 3

# ─── 8. Print summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║   AttackTrace is ready!                            ║${NC}"
echo -e "${BOLD}${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Frontend  →  http://localhost:3000               ║${NC}"
echo -e "${BOLD}${GREEN}║   API       →  http://localhost:8000               ║${NC}"
echo -e "${BOLD}${GREEN}║   API Docs  →  http://localhost:8000/api/v1/docs   ║${NC}"
echo -e "${BOLD}${GREEN}║   Flower    →  http://localhost:5555/flower        ║${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Login credentials:                               ║${NC}"
printf  "${BOLD}${GREEN}║     Username: %-36s║${NC}\n" "$ADMIN_EMAIL"
printf  "${BOLD}${GREEN}║     Password: %-36s║${NC}\n" "$ADMIN_PASS"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Invite code for new users: ATTACKTRACE           ║${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║   Useful commands:                                 ║${NC}"
echo -e "${BOLD}${GREEN}║     make logs        — tail all service logs       ║${NC}"
echo -e "${BOLD}${GREEN}║     make down        — stop everything             ║${NC}"
echo -e "${BOLD}${GREEN}║     make install-tools — install ffuf, nuclei etc  ║${NC}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
