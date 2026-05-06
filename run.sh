#!/usr/bin/env bash
# NEXUS — single-command start
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$SCRIPT_DIR/backend"
VENV="$SCRIPT_DIR/.venv"
ENV_FILE="$SCRIPT_DIR/.env"

# ---- Colour helpers ----
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[NEXUS]${NC} $*"; }
warn()  { echo -e "${YELLOW}[NEXUS]${NC} $*"; }
error() { echo -e "${RED}[NEXUS]${NC} $*" >&2; exit 1; }

# ---- .env bootstrap ----
if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
    warn ".env not found — copied from .env.example. Review it before scanning real targets."
  fi
fi

# ---- Python check ----
PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" &>/dev/null; then
    PYTHON="$candidate"
    break
  fi
done
[[ -z "$PYTHON" ]] && error "Python 3.10+ required but not found."

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Using Python $PY_VERSION ($PYTHON)"

# ---- Virtual env ----
if [[ ! -d "$VENV" ]]; then
  info "Creating virtualenv at .venv ..."
  "$PYTHON" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# ---- Dependencies ----
REQUIRED_PKGS="fastapi uvicorn httpx pydantic python-dotenv beautifulsoup4"
MISSING=()
for pkg in $REQUIRED_PKGS; do
  python -c "import ${pkg//-/_}" 2>/dev/null || MISSING+=("$pkg")
done
# uvicorn has extras
python -c "import uvicorn" 2>/dev/null || MISSING+=("uvicorn[standard]")

if [[ ${#MISSING[@]} -gt 0 ]]; then
  info "Installing: ${MISSING[*]}"
  pip install --quiet "${MISSING[@]}"
fi

# ---- Launch ----
info "Starting NEXUS backend on http://0.0.0.0:8000"
info "API docs: http://localhost:8000/docs"
echo ""
cd "$BACKEND"
exec python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
