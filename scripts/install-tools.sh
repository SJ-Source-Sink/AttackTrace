#!/usr/bin/env bash
# ─── AttackTrace — Tool Installer ─────────────────────────────────────────
#
# Installs ALL external tools required by AttackTrace:
#
#   Core scanners  : nmap, nuclei, ffuf, gowitness
#   Container/IaC  : trivy, checkov
#   Secrets        : trufflehog
#   Passive recon  : gau, waybackurls, cloudlist
#   Wordlists      : SecLists, nuclei-templates, bundled wordlists
#   Optional       : prowler (heavy, AWS-only CSPM)
#
# Usage:
#   chmod +x scripts/install-tools.sh
#   ./scripts/install-tools.sh           # full install
#   ./scripts/install-tools.sh --tools   # tools only (skip Python/Node deps)
#   ./scripts/install-tools.sh --check   # check what's installed
#   ./scripts/install-tools.sh --optional  # also install prowler
#
# Supports: macOS (Homebrew) · Debian/Ubuntu/Kali (apt + curl)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERR ]${NC}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}── $* ──${NC}"; }
skipped() { echo -e "${YELLOW}[SKIP]${NC}  $*"; }

TOOLS_ONLY=false
CHECK_ONLY=false
INSTALL_OPTIONAL=false

for arg in "$@"; do
  case "$arg" in
    --tools)    TOOLS_ONLY=true ;;
    --check)    CHECK_ONLY=true ;;
    --optional) INSTALL_OPTIONAL=true ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

need() { command -v "$1" >/dev/null 2>&1; }

# ─── Check mode ──────────────────────────────────────────────────────────────
if $CHECK_ONLY; then
  echo ""
  echo "AttackTrace — Installation Check"
  echo "================================="
  echo ""
  _ver() { ("$1" --version 2>&1 || "$1" -version 2>&1 || echo "installed") 2>/dev/null | head -1 | tr -d '\n' || true; }

  echo "Core tools:"
  for tool in nmap nuclei ffuf gowitness; do
    if need "$tool"; then
      echo -e "  ${GREEN}✓${NC} $tool  ${CYAN}$(_ver "$tool")${NC}"
    else
      echo -e "  ${RED}✗${NC} $tool  (not installed — run install-tools.sh)"
    fi
  done

  echo ""
  echo "Security scanners:"
  for tool in trivy checkov trufflehog prowler; do
    if need "$tool"; then
      echo -e "  ${GREEN}✓${NC} $tool  ${CYAN}$(_ver "$tool")${NC}"
    else
      echo -e "  ${YELLOW}-${NC} $tool  (optional — some scanners degraded)"
    fi
  done

  echo ""
  echo "Passive recon:"
  for tool in gau waybackurls cloudlist; do
    if need "$tool"; then
      echo -e "  ${GREEN}✓${NC} $tool  ${CYAN}$(_ver "$tool")${NC}"
    else
      echo -e "  ${YELLOW}-${NC} $tool  (optional)"
    fi
  done

  echo ""
  echo "Runtime:"
  for tool in git python3 node npm go docker; do
    if need "$tool"; then
      echo -e "  ${GREEN}✓${NC} $tool  ${CYAN}$(_ver "$tool")${NC}"
    else
      echo -e "  ${YELLOW}-${NC} $tool"
    fi
  done

  echo ""
  echo "Wordlists:"
  for wl in \
    "$REPO_ROOT/wordlists/web/common.txt" \
    "$REPO_ROOT/wordlists/dns/subdomains.txt" \
    "$REPO_ROOT/wordlists/api/endpoints.txt" \
    "$HOME/nuclei-templates" \
    "/opt/homebrew/share/seclists" \
    "/usr/share/seclists"; do
    if [ -e "$wl" ]; then
      echo -e "  ${GREEN}✓${NC} $wl"
    else
      echo -e "  ${YELLOW}-${NC} $wl (not installed)"
    fi
  done
  echo ""
  exit 0
fi

# ─── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        AttackTrace — Tool Installer                  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
info "OS: $OS ($ARCH)   Repo: $REPO_ROOT"

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ─── Shared helpers ──────────────────────────────────────────────────────────

install_go_tool() {
  local pkg="$1" binary="$2"
  if need "$binary"; then
    ok "$binary already installed"
    return
  fi
  if need go; then
    info "Installing $binary via go install…"
    GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$GOPATH/bin:$PATH"
    go install "$pkg"
    ok "$binary installed"
  else
    warn "Go not found — cannot install $binary. Install Go from https://go.dev/dl/ then re-run."
  fi
}

install_pip_tool() {
  local pkg="$1" binary="${2:-$1}"
  if need "$binary"; then
    ok "$binary already installed"
    return
  fi
  local pip_cmd
  pip_cmd="$(_find_pip)"
  if [ -z "$pip_cmd" ]; then
    warn "pip not found — cannot install $pkg"
    return
  fi
  info "Installing $pkg via pip…"
  $pip_cmd install -q "$pkg"
  ok "$binary installed"
}

_find_pip() {
  if [ -f "$REPO_ROOT/platform/backend/.venv/bin/pip" ]; then
    echo "$REPO_ROOT/platform/backend/.venv/bin/pip"
  elif need pip3; then
    echo "pip3"
  elif need pip; then
    echo "pip"
  else
    echo ""
  fi
}

# ─── macOS install ───────────────────────────────────────────────────────────

install_brew_tool() {
  local formula="$1" binary="${2:-$1}"
  if need "$binary"; then
    ok "$binary already installed"
  else
    info "Installing $formula via Homebrew…"
    brew install "$formula"
    ok "$binary installed"
  fi
}

install_macos() {
  if ! need brew; then
    err "Homebrew not found. Install it first: https://brew.sh"
    exit 1
  fi
  brew update --quiet

  header "Core Scanners (macOS)"
  install_brew_tool ffuf
  install_brew_tool nuclei
  install_brew_tool gowitness
  install_brew_tool nmap
  install_brew_tool go golang

  header "Security Scanners (macOS)"
  # trivy — container & IaC vulnerability scanner
  install_brew_tool trivy

  # trufflehog — secrets detection
  if need trufflehog; then
    ok "trufflehog already installed"
  else
    info "Installing trufflehog via Homebrew tap…"
    brew tap trufflesecurity/trufflehog 2>/dev/null || true
    brew install trufflesecurity/trufflehog/trufflehog
    ok "trufflehog installed"
  fi

  # checkov — IaC static analysis (pip package)
  install_pip_tool checkov

  header "Passive Recon Tools (macOS)"
  install_go_tool "github.com/lc/gau/v2/cmd/gau@latest" gau
  install_go_tool "github.com/tomnomnom/waybackurls@latest" waybackurls
  install_go_tool "github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest" cloudlist

  header "SecLists (macOS)"
  local sl_dir="/opt/homebrew/share/seclists"
  [ "$ARCH" = "x86_64" ] && sl_dir="/usr/local/share/seclists"
  if [ -d "$sl_dir" ]; then
    ok "SecLists already installed at $sl_dir"
  else
    info "Installing SecLists via Homebrew (large download, may take a while)…"
    brew install seclists
    ok "SecLists installed"
  fi
}

# ─── Linux install ───────────────────────────────────────────────────────────

install_linux() {
  $SUDO apt-get update -qq

  header "Core Scanners (Linux)"
  if need nmap; then ok "nmap already installed"
  else $SUDO apt-get install -y -qq nmap && ok "nmap installed"; fi

  if need go; then ok "Go already installed"
  else
    info "Installing Go via apt…"
    $SUDO apt-get install -y -qq golang-go
    ok "Go installed"
  fi

  install_go_tool "github.com/ffuf/ffuf/v2@latest" ffuf
  install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" nuclei
  install_go_tool "github.com/sensepost/gowitness@latest" gowitness

  header "Security Scanners (Linux)"
  # trivy — official install script (handles amd64 + arm64)
  if need trivy; then
    ok "trivy already installed"
  else
    info "Installing trivy via official install script…"
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | $SUDO sh -s -- -b /usr/local/bin
    ok "trivy installed"
  fi

  # trufflehog — official install script
  if need trufflehog; then
    ok "trufflehog already installed"
  else
    info "Installing trufflehog via official install script…"
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
      | $SUDO sh -s -- -b /usr/local/bin
    ok "trufflehog installed"
  fi

  # checkov — pip package
  install_pip_tool checkov

  header "Passive Recon Tools (Linux)"
  install_go_tool "github.com/lc/gau/v2/cmd/gau@latest" gau
  install_go_tool "github.com/tomnomnom/waybackurls@latest" waybackurls
  install_go_tool "github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest" cloudlist

  header "SecLists (Linux)"
  local sl_dir="/usr/share/seclists"
  if [ -d "$sl_dir" ]; then
    ok "SecLists already at $sl_dir"
  else
    info "Installing SecLists…"
    $SUDO apt-get install -y -qq seclists 2>/dev/null || {
      warn "Not in apt — cloning from GitHub (large download)…"
      $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$sl_dir"
    }
    ok "SecLists installed"
  fi
}

# ─── Optional heavy tools ────────────────────────────────────────────────────

install_optional() {
  header "Optional: Prowler (AWS/GCP/Azure CSPM)"
  if need prowler; then
    ok "prowler already installed"
  else
    info "Installing prowler via pip (this is large ~200MB)…"
    local pip_cmd
    pip_cmd="$(_find_pip)"
    if [ -n "$pip_cmd" ]; then
      $pip_cmd install -q prowler
      ok "prowler installed"
    else
      warn "pip not found — skipping prowler"
    fi
  fi
}

# ─── Nuclei templates ────────────────────────────────────────────────────────

install_nuclei_templates() {
  header "Nuclei Templates"
  local dir="$HOME/nuclei-templates"
  if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null | wc -l)" -gt 10 ]; then
    ok "nuclei-templates already at $dir"
    info "Pulling latest updates…"
    (cd "$dir" && git pull --quiet --ff-only 2>/dev/null) || true
  else
    info "Downloading nuclei-templates…"
    if need nuclei; then
      nuclei -update-templates -silent 2>/dev/null || \
        git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$dir"
    else
      git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$dir"
    fi
    ok "nuclei-templates installed at $dir"
  fi
}

# ─── Python deps ─────────────────────────────────────────────────────────────

install_python_deps() {
  header "Python Backend Dependencies"
  local req="$REPO_ROOT/platform/backend/requirements.txt"
  [ -f "$req" ] || { warn "requirements.txt not found at $req"; return; }

  local pip_cmd
  pip_cmd="$(_find_pip)"
  if [ -z "$pip_cmd" ]; then
    warn "pip not found — skipping Python deps"
    return
  fi

  $pip_cmd install -q -r "$req"
  ok "Python dependencies installed"

  # Install bundled attackmapper CLI (Attack Path Mapper feature)
  local am_pkg="$REPO_ROOT/tools/attackmapper"
  if [ -d "$am_pkg" ]; then
    info "Installing bundled attackmapper CLI…"
    $pip_cmd install -q "$am_pkg"
    ok "attackmapper CLI installed"
  else
    warn "tools/attackmapper not found — Attack Path Mapper will be unavailable"
  fi
}

# ─── Node / frontend deps ────────────────────────────────────────────────────

install_node_deps() {
  header "Node.js Frontend Dependencies"
  local fe="$REPO_ROOT/platform/frontend"
  [ -f "$fe/package.json" ] || { warn "Frontend package.json not found"; return; }

  if ! need node; then
    warn "Node.js not found — skipping frontend deps. Install from https://nodejs.org"
    return
  fi

  (cd "$fe" && npm install --silent)
  ok "Node.js dependencies installed"

  info "Installing Playwright browsers (Chromium)…"
  (cd "$fe" && npx playwright install chromium --with-deps 2>/dev/null) || \
    warn "Playwright install failed. Run manually: cd platform/frontend && npx playwright install chromium"
  ok "Playwright ready"
}

# ─── Bundled wordlists sanity check ──────────────────────────────────────────

check_bundled_wordlists() {
  header "Bundled Wordlists"
  local wl_dir="$REPO_ROOT/wordlists"
  local ok_count=0
  for f in \
    "$wl_dir/web/common.txt" \
    "$wl_dir/dns/subdomains.txt" \
    "$wl_dir/api/endpoints.txt"; do
    if [ -f "$f" ]; then
      local lines
      lines=$(wc -l < "$f" | tr -d ' ')
      ok "$(basename "$f")  ($lines lines)  →  $f"
      ok_count=$((ok_count + 1))
    else
      warn "Missing bundled wordlist: $f (check your git checkout)"
    fi
  done
  [ $ok_count -gt 0 ] && ok "Bundled wordlists ready ($ok_count files)"
}

# ─── Main ────────────────────────────────────────────────────────────────────

case "$OS" in
  Darwin) install_macos ;;
  Linux)  install_linux ;;
  *)      err "Unsupported OS: $OS"; exit 1 ;;
esac

install_nuclei_templates
check_bundled_wordlists

if ! $TOOLS_ONLY; then
  install_python_deps
  install_node_deps
fi

if $INSTALL_OPTIONAL; then
  install_optional
fi

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  All tools installed successfully!                   ║${NC}"
echo -e "${BOLD}${GREEN}║                                                      ║${NC}"
echo -e "${BOLD}${GREEN}║  Verify:  ./scripts/install-tools.sh --check         ║${NC}"
echo -e "${BOLD}${GREEN}║  Next:    cp .env.example .env  &&  make up          ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
