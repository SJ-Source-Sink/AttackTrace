#!/usr/bin/env bash
# ─── AttackTrace — Native Start (no Docker) ──────────────────────────────────
#
# Starts all AttackTrace services directly on the host machine.
# Requires: Python 3.11+, Node.js 18+, PostgreSQL, Redis
#
# Usage:
#   chmod +x start.sh && ./start.sh
#   make start
#
# Logs:  logs/backend.log  logs/worker.log  logs/beat.log  logs/frontend.log
# Stop:  ./stop.sh  (or: make stop)

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

# Extend PATH to pick up Homebrew postgres, node, etc.
export PATH="/opt/homebrew/opt/postgresql@16/bin:/opt/homebrew/opt/postgresql@15/bin:/opt/homebrew/opt/postgresql/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
BACKEND_DIR="$REPO_ROOT/platform/backend"
FRONTEND_DIR="$REPO_ROOT/platform/frontend"
PIDS_DIR="$REPO_ROOT/.pids"
LOGS_DIR="$REPO_ROOT/logs"

mkdir -p "$PIDS_DIR" "$LOGS_DIR"

echo ""
echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║       AttackTrace — Starting (native mode)         ║${NC}"
echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Find Python 3.11+ ─────────────────────────────────────────────────────
header "Checking prerequisites"

PYTHON=""
for candidate in python3.11 python3.12 python3.13 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    ver=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
    maj=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
    if [ "$maj" -eq 3 ] && [ "$ver" -ge 11 ]; then
      PYTHON="$candidate"
      break
    fi
  fi
done

[ -n "$PYTHON" ] || die "Python 3.11+ required. Install via: brew install python@3.11 (macOS) or apt install python3.11 (Linux)"
ok "Python: $($PYTHON --version)"

# Node.js 18+
if ! command -v node >/dev/null 2>&1; then
  die "Node.js 18+ required. Install from https://nodejs.org or: brew install node"
fi
NODE_VER=$(node -e "process.stdout.write(process.version.slice(1).split('.')[0])")
[ "$NODE_VER" -ge 18 ] || die "Node.js 18+ required (found v${NODE_VER}). Upgrade at https://nodejs.org"
ok "Node.js: $(node --version)"

# PostgreSQL client
if ! command -v psql >/dev/null 2>&1; then
  die "PostgreSQL not found. Install: brew install postgresql@16 (macOS) or apt install postgresql (Linux)"
fi
ok "PostgreSQL: $(psql --version | head -1)"

# Redis
if ! command -v redis-cli >/dev/null 2>&1; then
  die "Redis not found. Install: brew install redis (macOS) or apt install redis-server (Linux)"
fi
ok "Redis: $(redis-cli --version)"

# Check Redis is actually running
if ! redis-cli ping >/dev/null 2>&1; then
  warn "Redis is not running. Starting it..."
  if command -v brew >/dev/null 2>&1; then
    brew services start redis >/dev/null 2>&1 || redis-server --daemonize yes
  else
    redis-server --daemonize yes
  fi
  sleep 1
  redis-cli ping >/dev/null 2>&1 || die "Could not start Redis. Start it manually: redis-server"
fi
ok "Redis is running"

# ─── 2. Python virtual environment ───────────────────────────────────────────
header "Python environment"

VENV_DIR="$BACKEND_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
  info "Creating virtual environment..."
  "$PYTHON" -m venv "$VENV_DIR"
  ok "Created .venv"
else
  ok ".venv exists"
fi

PY="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"

info "Installing/updating Python dependencies..."
"$PIP" install --quiet --upgrade pip
"$PIP" install --quiet -r "$BACKEND_DIR/requirements.txt"
"$PIP" install --quiet -e "$REPO_ROOT" 2>/dev/null || true
ok "Python dependencies installed"

# ─── 3. Frontend dependencies ─────────────────────────────────────────────────
header "Frontend"

if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
  info "Installing frontend dependencies (first time, may take a minute)..."
  npm --prefix "$FRONTEND_DIR" install --silent
  ok "Node modules installed"
else
  # Quick check — only reinstall if package.json changed
  if [ "$FRONTEND_DIR/package.json" -nt "$FRONTEND_DIR/node_modules/.package-lock.json" ] 2>/dev/null; then
    info "package.json changed — reinstalling..."
    npm --prefix "$FRONTEND_DIR" install --silent
    ok "Node modules updated"
  else
    ok "Node modules up to date"
  fi
fi

# ─── 4. Environment configuration ─────────────────────────────────────────────
header "Environment"

BACKEND_ENV="$BACKEND_DIR/.env"

if [ ! -f "$BACKEND_ENV" ]; then
  info "Creating backend .env from defaults..."

  # Generate secrets
  if command -v openssl >/dev/null 2>&1; then
    SECRET_KEY=$(openssl rand -hex 32)
    KMS_KEY=$(openssl rand -base64 32)
  else
    SECRET_KEY=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
    KMS_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  fi

  cat > "$BACKEND_ENV" <<EOF
# AttackTrace backend config (native / no-Docker mode)
DATABASE_URL=postgresql+asyncpg://attacktrace:attacktrace@localhost:5432/attacktrace
SYNC_DATABASE_URL=postgresql://attacktrace:attacktrace@localhost:5432/attacktrace
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2
SECRET_KEY=${SECRET_KEY}
KMS_MASTER_KEY=${KMS_KEY}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480
REFRESH_TOKEN_EXPIRE_DAYS=7
ENVIRONMENT=development
DEBUG=false
FIRST_SUPERUSER_EMAIL=admin
FIRST_SUPERUSER_PASSWORD=Ihate13\$
ATTACKTRACE_WORKSPACE_DIR=${HOME}/.attacktrace/scans
ANTHROPIC_API_KEY=
AI_MODEL=claude-haiku-4-5-20251001
EOF
  ok "Created $BACKEND_ENV"
else
  ok "Backend .env exists"
fi

# Frontend .env.local
FRONTEND_ENV="$FRONTEND_DIR/.env.local"
if [ ! -f "$FRONTEND_ENV" ]; then
  echo "NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1" > "$FRONTEND_ENV"
  ok "Created frontend .env.local"
else
  ok "Frontend .env.local exists"
fi

# Source backend env vars for this script's DB operations
set -a; source "$BACKEND_ENV"; set +a
WORKSPACE_DIR="${ATTACKTRACE_WORKSPACE_DIR:-$HOME/.attacktrace/scans}"
mkdir -p "$WORKSPACE_DIR"

# ─── 5. PostgreSQL setup ──────────────────────────────────────────────────────
header "Database"

# Check if postgres is running
if ! pg_isready -q 2>/dev/null; then
  warn "PostgreSQL is not running. Attempting to start..."
  if command -v brew >/dev/null 2>&1; then
    brew services start postgresql@16 2>/dev/null || \
    brew services start postgresql 2>/dev/null || true
  elif command -v pg_ctlcluster >/dev/null 2>&1; then
    sudo service postgresql start 2>/dev/null || true
  fi
  sleep 2
  pg_isready -q || die "PostgreSQL not running. Start it manually."
fi
ok "PostgreSQL is running"

# Determine the postgres superuser (Homebrew uses current OS user; Linux uses 'postgres')
PG_SUPERUSER=""
for candidate in "$USER" postgres; do
  if psql -U "$candidate" -c "" postgres >/dev/null 2>&1; then
    PG_SUPERUSER="$candidate"
    break
  fi
done
[ -n "$PG_SUPERUSER" ] || die "Cannot connect to PostgreSQL as any superuser. Check that PostgreSQL is running and your user has access."

# Create role if missing
psql -U "$PG_SUPERUSER" -tc "SELECT 1 FROM pg_roles WHERE rolname='attacktrace'" postgres 2>/dev/null | grep -q 1 || \
  psql -U "$PG_SUPERUSER" -c "CREATE USER attacktrace WITH PASSWORD 'attacktrace';" postgres >/dev/null 2>&1

# Create database if missing
psql -U "$PG_SUPERUSER" -tc "SELECT 1 FROM pg_database WHERE datname='attacktrace'" postgres 2>/dev/null | grep -q 1 || \
  psql -U "$PG_SUPERUSER" -c "CREATE DATABASE attacktrace OWNER attacktrace;" postgres >/dev/null 2>&1

ok "Database 'attacktrace' ready"

# ─── 6. Migrations + seed ─────────────────────────────────────────────────────
header "Migrations"

cd "$BACKEND_DIR"
"$VENV_DIR/bin/alembic" upgrade head
ok "Migrations up to date"

info "Seeding initial data..."
"$PY" -m app.initial_data 2>&1 | grep -v "bcrypt\|AttributeError\|passlib" || true
ok "Seed complete"

cd "$REPO_ROOT"

# ─── 7. Kill any existing processes ──────────────────────────────────────────
header "Starting services"

kill_if_running() {
  local pidfile="$PIDS_DIR/$1.pid"
  if [ -f "$pidfile" ]; then
    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && info "Stopped old $1 (pid $pid)"
    fi
    rm -f "$pidfile"
  fi
}

kill_if_running backend
kill_if_running worker
kill_if_running beat
kill_if_running frontend
sleep 1

UVICORN="$VENV_DIR/bin/uvicorn"
CELERY="$VENV_DIR/bin/celery"

# Backend
info "Starting backend (FastAPI)..."
cd "$BACKEND_DIR"
"$UVICORN" app.main:app --host 0.0.0.0 --port 8000 --reload \
  > "$LOGS_DIR/backend.log" 2>&1 &
echo $! > "$PIDS_DIR/backend.pid"
ok "Backend started (pid $(cat "$PIDS_DIR/backend.pid")) → logs/backend.log"

# Celery worker
info "Starting Celery worker..."
"$CELERY" -A app.workers.celery_app worker \
  --loglevel=warning --concurrency=4 -Q scans,default \
  > "$LOGS_DIR/worker.log" 2>&1 &
echo $! > "$PIDS_DIR/worker.pid"
ok "Worker started (pid $(cat "$PIDS_DIR/worker.pid")) → logs/worker.log"

# Celery beat
info "Starting Celery beat..."
"$CELERY" -A app.workers.celery_app beat \
  --loglevel=warning \
  > "$LOGS_DIR/beat.log" 2>&1 &
echo $! > "$PIDS_DIR/beat.pid"
ok "Beat started (pid $(cat "$PIDS_DIR/beat.pid")) → logs/beat.log"

cd "$REPO_ROOT"

# Frontend
info "Starting frontend (Next.js)..."
npm --prefix "$FRONTEND_DIR" run dev \
  > "$LOGS_DIR/frontend.log" 2>&1 &
echo $! > "$PIDS_DIR/frontend.pid"
ok "Frontend started (pid $(cat "$PIDS_DIR/frontend.pid")) → logs/frontend.log"

# ─── 8. Wait for backend to be ready ─────────────────────────────────────────
info "Waiting for backend to be ready..."
RETRIES=20
until curl -sf http://localhost:8000/health >/dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  if [ $RETRIES -le 0 ]; then
    warn "Backend didn't start in time. Check: tail -f logs/backend.log"
    break
  fi
  sleep 2
done
[ $RETRIES -gt 0 ] && ok "Backend is ready"

# ─── 9. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║   AttackTrace is running!                          ║${NC}"
echo -e "${BOLD}${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Frontend  →  http://localhost:3000               ║${NC}"
echo -e "${BOLD}${GREEN}║   API       →  http://localhost:8000               ║${NC}"
echo -e "${BOLD}${GREEN}║   API Docs  →  http://localhost:8000/api/v1/docs   ║${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Login:  admin / Ihate13\$                         ║${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Logs:                                            ║${NC}"
echo -e "${BOLD}${GREEN}║     tail -f logs/backend.log                       ║${NC}"
echo -e "${BOLD}${GREEN}║     tail -f logs/frontend.log                      ║${NC}"
echo -e "${BOLD}${GREEN}║                                                    ║${NC}"
echo -e "${BOLD}${GREEN}║   Stop:  ./stop.sh  (or: make stop)                ║${NC}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
