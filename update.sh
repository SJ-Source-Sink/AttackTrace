#!/usr/bin/env bash
# ─── AttackTrace — One-Command Update ────────────────────────────────────────
#
# Pull the latest changes from GitHub and hot-update the running platform.
#
# Usage:
#   chmod +x update.sh && ./update.sh
#   make update
#
# What this does:
#   1. Pulls latest code from GitHub
#   2. Detects which services need a rebuild (backend/worker, frontend)
#   3. Rebuilds only the changed images
#   4. Runs any new database migrations (safe / idempotent)
#   5. Restarts affected containers with near-zero downtime
#   6. Confirms everything is healthy
#
# Safe to run anytime — data volumes are never touched.

set -euo pipefail

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
echo -e "${BOLD}${CYAN}║          AttackTrace — Update                      ║${NC}"
echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Docker Compose binary ────────────────────────────────────────────────────
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  die "Docker Compose not found. Install Docker Desktop."
fi

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running. Start Docker Desktop and try again."
fi

if [ ! -f ".env" ]; then
  die ".env not found. Run setup.sh first."
fi

# ─── 1. Git pull ──────────────────────────────────────────────────────────────
header "Pulling latest changes from GitHub"

# Make sure we're on a branch that tracks a remote
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
info "Branch: ${CURRENT_BRANCH}"

# Record the commit we're on before pulling
OLD_COMMIT=$(git rev-parse HEAD)

if ! git fetch origin "$CURRENT_BRANCH" 2>&1 | grep -v "^$"; then
  warn "git fetch failed — check network/GitHub access."
fi

REMOTE_COMMIT=$(git rev-parse "origin/${CURRENT_BRANCH}" 2>/dev/null || echo "")

if [ -z "$REMOTE_COMMIT" ]; then
  warn "Could not determine remote commit. Continuing anyway."
elif [ "$OLD_COMMIT" = "$REMOTE_COMMIT" ]; then
  ok "Already up to date — no changes to pull."
  NEW_COMMIT="$OLD_COMMIT"
else
  git pull origin "$CURRENT_BRANCH"
  NEW_COMMIT=$(git rev-parse HEAD)
  ok "Updated from ${OLD_COMMIT:0:7} → ${NEW_COMMIT:0:7}"

  # Show what changed
  info "Changes:"
  git log --oneline "${OLD_COMMIT}..${NEW_COMMIT}" | sed 's/^/     /'
fi

NEW_COMMIT=${NEW_COMMIT:-$(git rev-parse HEAD)}

# ─── 2. Detect which services need rebuilding ─────────────────────────────────
header "Detecting changes"

REBUILD_BACKEND=false
REBUILD_FRONTEND=false

if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
  CHANGED=$(git diff --name-only "${OLD_COMMIT}" "${NEW_COMMIT}" 2>/dev/null || echo "")

  # Backend: any Python source, requirements, Dockerfile, or migrations
  if echo "$CHANGED" | grep -qE '^(platform/backend/|requirements.*\.txt|pyproject\.toml|attacktrace/)'; then
    REBUILD_BACKEND=true
    info "Backend source changed — will rebuild backend + worker images"
  fi

  # Frontend: any Next.js/TypeScript source, package.json, or Dockerfile
  if echo "$CHANGED" | grep -qE '^platform/frontend/'; then
    REBUILD_FRONTEND=true
    info "Frontend source changed — will rebuild frontend image"
  fi
else
  warn "No new commits — forcing rebuild of all services."
  REBUILD_BACKEND=true
  REBUILD_FRONTEND=true
fi

if [ "$REBUILD_BACKEND" = false ] && [ "$REBUILD_FRONTEND" = false ]; then
  ok "No service rebuilds needed."
fi

# ─── 3. Rebuild changed images ────────────────────────────────────────────────
if [ "$REBUILD_BACKEND" = true ] || [ "$REBUILD_FRONTEND" = true ]; then
  header "Rebuilding images"

  if [ "$REBUILD_BACKEND" = true ] && [ "$REBUILD_FRONTEND" = true ]; then
    info "Rebuilding backend + worker + frontend..."
    $DC build backend worker frontend
  elif [ "$REBUILD_BACKEND" = true ]; then
    info "Rebuilding backend + worker..."
    $DC build backend worker
  else
    info "Rebuilding frontend..."
    $DC build frontend
  fi
  ok "Images rebuilt"
fi

# ─── 4. Run database migrations ───────────────────────────────────────────────
header "Running migrations"
info "Applying any new Alembic migrations..."

# Ensure backend is running (it might have been stopped)
$DC up -d backend

# Wait up to 30s for backend to be healthy
RETRIES=15
until $DC exec -T backend curl -sf http://localhost:8000/health >/dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  if [ $RETRIES -le 0 ]; then
    warn "Backend health check timed out — trying migrations anyway..."
    break
  fi
  sleep 2
done

$DC exec -T backend alembic upgrade head
ok "Migrations up to date"

# ─── 5. Restart affected services ─────────────────────────────────────────────
header "Restarting services"

if [ "$REBUILD_BACKEND" = true ]; then
  info "Restarting backend..."
  $DC up -d --no-deps backend
  info "Restarting worker..."
  $DC up -d --no-deps worker
  info "Restarting worker-beat..."
  $DC up -d --no-deps worker-beat
fi

if [ "$REBUILD_FRONTEND" = true ]; then
  info "Restarting frontend..."
  $DC up -d --no-deps frontend
fi

ok "Services restarted"

# ─── 6. Health check ──────────────────────────────────────────────────────────
header "Health check"

sleep 3

BACKEND_OK=false
FRONTEND_OK=false

if $DC exec -T backend curl -sf http://localhost:8000/health >/dev/null 2>&1; then
  ok "Backend healthy"
  BACKEND_OK=true
else
  warn "Backend not responding — check: make backend-logs"
fi

if $DC exec -T frontend curl -sf http://localhost:3000 >/dev/null 2>&1; then
  ok "Frontend healthy"
  FRONTEND_OK=true
else
  warn "Frontend not yet ready (may still be compiling) — check: make logs"
fi

# ─── 7. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║   AttackTrace updated!                             ║${NC}"
echo -e "${BOLD}${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
printf  "${BOLD}${GREEN}║   Commit: %-40s║${NC}\n" "${NEW_COMMIT:0:7}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Frontend  →  http://localhost:3000               ║${NC}"
echo -e "${BOLD}${GREEN}║   API       →  http://localhost:8000               ║${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Useful commands:                                 ║${NC}"
echo -e "${BOLD}${GREEN}║     make logs         — tail all service logs      ║${NC}"
echo -e "${BOLD}${GREEN}║     make backend-logs — backend only               ║${NC}"
echo -e "${BOLD}${GREEN}║     make ps           — container status           ║${NC}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
