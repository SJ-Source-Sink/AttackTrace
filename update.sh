#!/usr/bin/env bash
# ─── AttackTrace — One-Command Seamless Update ───────────────────────────────
#
# Pulls the latest changes from GitHub and hot-updates the running platform.
# Auto-detects whether you're running in Docker mode or native mode.
#
# Usage:
#   chmod +x update.sh && ./update.sh
#   make update
#
# Docker mode  — detects running Docker containers, rebuilds only changed
#                images, runs migrations, restarts affected services.
#
# Native mode  — detects running .pids files, updates pip/npm deps if needed,
#                runs migrations, restarts only affected services in-place.
#
# Safe to run anytime — data volumes and .env files are never touched.

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

BACKEND_DIR="$REPO_ROOT/platform/backend"
FRONTEND_DIR="$REPO_ROOT/platform/frontend"
PIDS_DIR="$REPO_ROOT/.pids"
LOGS_DIR="$REPO_ROOT/logs"

# ─── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║          AttackTrace — Seamless Update             ║${NC}"
echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Detect mode ──────────────────────────────────────────────────────────────
MODE=""

# Docker mode: Docker is available and at least the backend container exists
if docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
  else
    DC="docker-compose"
  fi
  if docker info >/dev/null 2>&1; then
    # Check if any AttackTrace containers are running OR have been created
    if $DC ps --format json 2>/dev/null | grep -q "attacktrace\|backend\|frontend\|worker" 2>/dev/null || \
       $DC ps 2>/dev/null | grep -qE "backend|frontend|worker|postgres|redis" 2>/dev/null; then
      MODE="docker"
    fi
  fi
fi

# Native mode: .pids directory has at least one PID file
if [ -z "$MODE" ] && [ -d "$PIDS_DIR" ] && ls "$PIDS_DIR"/*.pid >/dev/null 2>&1; then
  MODE="native"
fi

# Fallback: if neither detected, use Docker if available, native otherwise
if [ -z "$MODE" ]; then
  if [ -n "${DC:-}" ] && docker info >/dev/null 2>&1 && [ -f ".env" ]; then
    MODE="docker"
    warn "No running containers detected — will update and restart in Docker mode."
  else
    MODE="native"
    warn "No running services detected — will update in native mode."
  fi
fi

echo -e "  Mode: ${BOLD}${CYAN}${MODE}${NC}"

# ─── 1. Git pull ──────────────────────────────────────────────────────────────
header "Pulling latest changes from GitHub"

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
info "Branch: ${CURRENT_BRANCH}"
OLD_COMMIT=$(git rev-parse HEAD)

git fetch origin "$CURRENT_BRANCH" 2>&1 | grep -v "^$" || warn "git fetch failed — check network/GitHub access."

REMOTE_COMMIT=$(git rev-parse "origin/${CURRENT_BRANCH}" 2>/dev/null || echo "")

if [ -z "$REMOTE_COMMIT" ]; then
  warn "Could not determine remote commit — continuing with local state."
  NEW_COMMIT="$OLD_COMMIT"
elif [ "$OLD_COMMIT" = "$REMOTE_COMMIT" ]; then
  ok "Already up to date (${OLD_COMMIT:0:7}) — no new commits."
  NEW_COMMIT="$OLD_COMMIT"
  ALREADY_UP_TO_DATE=true
else
  git pull origin "$CURRENT_BRANCH"
  NEW_COMMIT=$(git rev-parse HEAD)
  ok "Updated: ${OLD_COMMIT:0:7} → ${NEW_COMMIT:0:7}"
  info "Changes:"
  git log --oneline "${OLD_COMMIT}..${NEW_COMMIT}" | sed 's/^/     /'
  ALREADY_UP_TO_DATE=false
fi

NEW_COMMIT=${NEW_COMMIT:-$(git rev-parse HEAD)}
ALREADY_UP_TO_DATE=${ALREADY_UP_TO_DATE:-false}

# ─── 2. Detect what changed ───────────────────────────────────────────────────
header "Detecting changes"

BACKEND_CHANGED=false
FRONTEND_CHANGED=false
MIGRATIONS_EXIST=false

if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
  CHANGED=$(git diff --name-only "${OLD_COMMIT}" "${NEW_COMMIT}" 2>/dev/null || echo "")

  if echo "$CHANGED" | grep -qE '^(platform/backend/|requirements.*\.txt|pyproject\.toml)'; then
    BACKEND_CHANGED=true
    info "Backend source changed"
  fi

  if echo "$CHANGED" | grep -qE '^platform/backend/alembic/'; then
    MIGRATIONS_EXIST=true
    info "New database migrations detected"
  fi

  if echo "$CHANGED" | grep -qE '^platform/frontend/'; then
    FRONTEND_CHANGED=true
    info "Frontend source changed"
  fi
else
  # Force rebuild everything when already up to date (manual re-apply)
  warn "No new commits — forcing full update."
  BACKEND_CHANGED=true
  FRONTEND_CHANGED=true
fi

if [ "$BACKEND_CHANGED" = false ] && [ "$FRONTEND_CHANGED" = false ]; then
  ok "No service rebuilds needed."
fi


# ══════════════════════════════════════════════════════════════════════════════
#  DOCKER MODE
# ══════════════════════════════════════════════════════════════════════════════
if [ "$MODE" = "docker" ]; then

  if [ ! -f ".env" ]; then
    die ".env not found. Run ./setup.sh first."
  fi

  # ── Rebuild changed images ──────────────────────────────────────────────────
  if [ "$BACKEND_CHANGED" = true ] || [ "$FRONTEND_CHANGED" = true ]; then
    header "Rebuilding Docker images"

    if [ "$BACKEND_CHANGED" = true ] && [ "$FRONTEND_CHANGED" = true ]; then
      info "Rebuilding backend + worker + frontend..."
      $DC build backend worker frontend
    elif [ "$BACKEND_CHANGED" = true ]; then
      info "Rebuilding backend + worker..."
      $DC build backend worker
    else
      info "Rebuilding frontend..."
      $DC build frontend
    fi
    ok "Images rebuilt"
  fi

  # ── Run migrations ──────────────────────────────────────────────────────────
  header "Running migrations"
  info "Ensuring backend container is up..."
  $DC up -d backend

  RETRIES=15
  until $DC exec -T backend curl -sf http://localhost:8000/health >/dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    [ $RETRIES -le 0 ] && { warn "Backend health check timed out — trying migrations anyway..."; break; }
    sleep 2
  done

  $DC exec -T backend alembic upgrade head
  ok "Migrations up to date"

  # ── Restart affected services ───────────────────────────────────────────────
  header "Restarting services"

  if [ "$BACKEND_CHANGED" = true ]; then
    info "Restarting backend..."
    $DC up -d --no-deps backend
    info "Restarting worker..."
    $DC up -d --no-deps worker
    info "Restarting worker-beat..."
    $DC up -d --no-deps worker-beat
    ok "Backend services restarted"
  fi

  if [ "$FRONTEND_CHANGED" = true ]; then
    info "Restarting frontend..."
    $DC up -d --no-deps frontend
    ok "Frontend restarted"
  fi

  # ── Health check ────────────────────────────────────────────────────────────
  header "Health check"
  sleep 3

  if $DC exec -T backend curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    ok "Backend healthy"
  else
    warn "Backend not responding — check: make backend-logs"
  fi

  if $DC exec -T frontend curl -sf http://localhost:3000 >/dev/null 2>&1; then
    ok "Frontend healthy"
  else
    warn "Frontend may still be compiling — check: make logs"
  fi

  # ── Summary ─────────────────────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${GREEN}║   AttackTrace updated! (Docker)                    ║${NC}"
  echo -e "${BOLD}${GREEN}╠════════════════════════════════════════════════════╣${NC}"
  printf  "${BOLD}${GREEN}║   Commit: %-40s║${NC}\n" "${NEW_COMMIT:0:7}"
  echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
  echo -e "${BOLD}${GREEN}║   Frontend  →  http://localhost:3000               ║${NC}"
  echo -e "${BOLD}${GREEN}║   API       →  http://localhost:8000               ║${NC}"
  echo -e "${BOLD}${GREEN}║   Flower    →  http://localhost:5555/flower        ║${NC}"
  echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
  echo -e "${BOLD}${GREEN}║   make logs          — tail all service logs       ║${NC}"
  echo -e "${BOLD}${GREEN}║   make backend-logs  — backend only                ║${NC}"
  echo -e "${BOLD}${GREEN}║   make ps            — container status            ║${NC}"
  echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════╝${NC}"
  echo ""
  exit 0
fi


# ══════════════════════════════════════════════════════════════════════════════
#  NATIVE MODE
# ══════════════════════════════════════════════════════════════════════════════

export PATH="/opt/homebrew/opt/postgresql@16/bin:/opt/homebrew/opt/postgresql@15/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

VENV_DIR="$BACKEND_DIR/.venv"
PY="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"
ALEMBIC="$VENV_DIR/bin/alembic"
UVICORN="$VENV_DIR/bin/uvicorn"
CELERY="$VENV_DIR/bin/celery"

[ -d "$VENV_DIR" ] || die "Virtual environment not found at $VENV_DIR. Run ./setup.sh first."
[ -f "$BACKEND_DIR/.env" ] || die ".env not found at $BACKEND_DIR/.env. Run ./setup.sh first."

mkdir -p "$PIDS_DIR" "$LOGS_DIR"

# ── Update Python dependencies ──────────────────────────────────────────────
if [ "$BACKEND_CHANGED" = true ]; then
  header "Updating Python dependencies"
  info "Installing any new requirements..."
  "$PIP" install --quiet --upgrade pip
  "$PIP" install --quiet -r "$BACKEND_DIR/requirements.txt"
  ok "Python dependencies up to date"
fi

# ── Update frontend dependencies ─────────────────────────────────────────────
if [ "$FRONTEND_CHANGED" = true ]; then
  header "Updating frontend dependencies"
  if [ "$FRONTEND_DIR/package.json" -nt "$FRONTEND_DIR/node_modules/.package-lock.json" ] 2>/dev/null; then
    info "package.json changed — reinstalling npm packages..."
    npm --prefix "$FRONTEND_DIR" install --silent
    ok "Node modules updated"
  else
    ok "Node modules up to date"
  fi
fi

# ── Run migrations ────────────────────────────────────────────────────────────
header "Running migrations"
set -a; source "$BACKEND_DIR/.env"; set +a
cd "$BACKEND_DIR"
"$ALEMBIC" upgrade head
ok "Migrations up to date"
cd "$REPO_ROOT"

# ── Gracefully restart affected services ──────────────────────────────────────
header "Restarting services"

restart_service() {
  local name="$1"
  local pidfile="$PIDS_DIR/${name}.pid"

  if [ -f "$pidfile" ]; then
    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      # Wait up to 5s for clean exit
      local waited=0
      while kill -0 "$pid" 2>/dev/null && [ $waited -lt 5 ]; do
        sleep 1
        waited=$((waited + 1))
      done
      # Force kill if still running
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

if [ "$BACKEND_CHANGED" = true ]; then
  # If uvicorn is running with --reload it auto-picks up file changes.
  # We only need a hard restart when the process isn't running at all.
  BACKEND_PID=""
  [ -f "$PIDS_DIR/backend.pid" ] && BACKEND_PID=$(cat "$PIDS_DIR/backend.pid")

  if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    # Running with --reload: touch any Python file to trigger reload
    touch "$BACKEND_DIR/app/main.py"
    ok "Backend reload triggered (--reload detected file change)"
  else
    # Not running or no PID — start fresh
    info "Starting backend..."
    restart_service backend
    cd "$BACKEND_DIR"
    "$UVICORN" app.main:app --host 0.0.0.0 --port 8000 --reload \
      > "$LOGS_DIR/backend.log" 2>&1 &
    echo $! > "$PIDS_DIR/backend.pid"
    ok "Backend started (pid $(cat "$PIDS_DIR/backend.pid"))"
    cd "$REPO_ROOT"
  fi

  # Always restart Celery (doesn't auto-reload)
  info "Restarting Celery worker..."
  restart_service worker
  cd "$BACKEND_DIR"
  "$CELERY" -A app.workers.celery_app worker \
    --loglevel=warning --concurrency=4 -Q scans,default,ai \
    > "$LOGS_DIR/worker.log" 2>&1 &
  echo $! > "$PIDS_DIR/worker.pid"
  ok "Worker restarted (pid $(cat "$PIDS_DIR/worker.pid"))"

  info "Restarting Celery beat..."
  restart_service beat
  "$CELERY" -A app.workers.celery_app beat \
    --loglevel=warning \
    > "$LOGS_DIR/beat.log" 2>&1 &
  echo $! > "$PIDS_DIR/beat.pid"
  ok "Beat restarted (pid $(cat "$PIDS_DIR/beat.pid"))"

  cd "$REPO_ROOT"
fi

if [ "$FRONTEND_CHANGED" = true ]; then
  info "Restarting frontend..."
  restart_service frontend
  npm --prefix "$FRONTEND_DIR" run dev \
    > "$LOGS_DIR/frontend.log" 2>&1 &
  echo $! > "$PIDS_DIR/frontend.pid"
  ok "Frontend restarted (pid $(cat "$PIDS_DIR/frontend.pid"))"
fi

# ── Health check ──────────────────────────────────────────────────────────────
header "Health check"

if [ "$BACKEND_CHANGED" = true ]; then
  info "Waiting for backend to be ready..."
  RETRIES=20
  until curl -sf http://localhost:8000/health >/dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    [ $RETRIES -le 0 ] && { warn "Backend didn't start in time — check: tail -f logs/backend.log"; break; }
    sleep 2
  done
  [ $RETRIES -gt 0 ] && ok "Backend healthy"
fi

if ! [ "$BACKEND_CHANGED" = true ] && ! [ "$FRONTEND_CHANGED" = true ]; then
  # Nothing was restarted — just verify existing services
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    ok "Backend healthy (no restart needed)"
  else
    warn "Backend not responding — check: tail -f logs/backend.log"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║   AttackTrace updated! (native)                    ║${NC}"
echo -e "${BOLD}${GREEN}╠════════════════════════════════════════════════════╣${NC}"
printf  "${BOLD}${GREEN}║   Commit: %-40s║${NC}\n" "${NEW_COMMIT:0:7}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Frontend  →  http://localhost:3000               ║${NC}"
echo -e "${BOLD}${GREEN}║   API       →  http://localhost:8000               ║${NC}"
echo -e "${BOLD}${GREEN}║   API Docs  →  http://localhost:8000/api/v1/docs   ║${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   make native-logs   — tail all service logs       ║${NC}"
echo -e "${BOLD}${GREEN}║   tail -f logs/backend.log                         ║${NC}"
echo -e "${BOLD}${GREEN}║   Stop:  ./stop.sh   (or: make stop)               ║${NC}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
