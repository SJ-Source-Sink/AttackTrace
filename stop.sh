#!/usr/bin/env bash
# ─── AttackTrace — Stop (native mode) ────────────────────────────────────────
#
# Stops all AttackTrace services started by start.sh
#
# Usage:
#   ./stop.sh
#   make stop

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${CYAN}  ▸${NC} $*"; }
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDS_DIR="$REPO_ROOT/.pids"

echo ""
echo -e "${BOLD}${CYAN}── Stopping AttackTrace ──${NC}"
echo ""

stop_service() {
  local name="$1"
  local pidfile="$PIDS_DIR/${name}.pid"

  if [ ! -f "$pidfile" ]; then
    warn "$name: not running (no pid file)"
    return
  fi

  local pid
  pid=$(cat "$pidfile")

  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    # Wait up to 5s for clean exit
    local i=0
    while kill -0 "$pid" 2>/dev/null && [ $i -lt 10 ]; do
      sleep 0.5; i=$((i+1))
    done
    # Force kill if still running
    kill -9 "$pid" 2>/dev/null || true
    ok "Stopped $name (pid $pid)"
  else
    warn "$name (pid $pid): already stopped"
  fi

  rm -f "$pidfile"
}

stop_service frontend
stop_service beat
stop_service worker
stop_service backend
stop_service msra

echo ""
ok "All services stopped."
echo ""
