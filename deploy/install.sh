#!/usr/bin/env bash
# Kali Pentest MCP — one-shot installer / deployment helper.
#
#   deploy/install.sh [--check] [--tools] [--user|--system] [--port N]
#
#   (default)   create .venv, install Python deps, seed scope.yaml
#   --check     report which external scanner tools are missing (no changes)
#   --tools     apt-get install missing scanner tools (needs sudo)
#   --user      install & start a user systemd service (no sudo)
#   --system    install & start a system systemd service (needs sudo)
#   --port N    web GUI port for the service (default 8080)
#
# Idempotent and safe: never overwrites an existing scope.yaml.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

SERVICE="kpm-webgui"
PORT="8080"
MODE=""
DO_TOOLS=0
DO_CHECK=0

TOOLS=(nmap nikto gobuster ffuf dirb feroxbuster nuclei httpx-toolkit
       whatweb wafw00f dnsrecon sqlmap wpscan wapiti curl)

usage() { sed -n '2,16p' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check)  DO_CHECK=1 ;;
    --tools)  DO_TOOLS=1 ;;
    --user)   MODE="user" ;;
    --system) MODE="system" ;;
    --port)   PORT="${2:?--port needs a value}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

missing_tools() {
  local missing=()
  for t in "${TOOLS[@]}"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  ((${#missing[@]})) && printf '%s\n' "${missing[@]}" || true
}

if [ "$DO_CHECK" = 1 ]; then
  echo "Project : $PROJECT_DIR"
  echo "Python  : $(python3 --version 2>&1 || echo 'python3 not found')"
  echo "Venv    : $([ -x .venv/bin/python ] && echo present || echo missing)"
  missing="$(missing_tools)"
  if [ -n "$missing" ]; then
    echo "Missing scanner tools:"
    echo "$missing" | sed 's/^/  - /'
    exit 1
  fi
  echo "All scanner tools present."
  exit 0
fi

if [ "$DO_TOOLS" = 1 ]; then
  missing="$(missing_tools)"
  if [ -z "$missing" ]; then
    echo "[install] no missing tools."
  else
    echo "[install] installing: $(echo "$missing" | tr '\n' ' ')"
    sudo apt-get update
    while read -r pkg; do
      [ -n "$pkg" ] || continue
      sudo apt-get install -y --no-install-recommends "$pkg" \
        || echo "[install] '$pkg' unavailable via apt — install it manually."
    done <<< "$missing"
  fi
fi

# --- Python environment -----------------------------------------------------
if [ ! -x .venv/bin/python ]; then
  echo "[install] creating .venv"
  python3 -m venv .venv
fi
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -r requirements.txt

# --- Scope seeding ----------------------------------------------------------
if [ ! -f scope.yaml ] && [ -f scope.yaml.example ]; then
  cp scope.yaml.example scope.yaml
  echo "[install] created scope.yaml from template — EDIT IT before scanning."
fi
if [ ! -f scope.txt ] && [ -f scope.txt.example ]; then
  cp scope.txt.example scope.txt
fi

# --- systemd ----------------------------------------------------------------
if [ -n "$MODE" ]; then
  PY="$PROJECT_DIR/.venv/bin/python"
  if [ "$MODE" = "user" ]; then
    UNIT_DIR="$HOME/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    sed -e "s#%h#$HOME#g" -e "s#--port 8080#--port $PORT#" \
      deploy/kpm-webgui.user.service > "$UNIT_DIR/$SERVICE.service"
    systemctl --user daemon-reload
    systemctl --user enable --now "$SERVICE.service"
    echo "[install] user service started: systemctl --user status $SERVICE"
    echo "[install] tip: 'loginctl enable-linger $USER' to run without login."
  else
    UNIT_DIR="/etc/systemd/system"
    sed -e "s#^User=.*#User=$USER#" \
        -e "s#^WorkingDirectory=.*#WorkingDirectory=$PROJECT_DIR#" \
        -e "s#^ExecStart=.*#ExecStart=$PY -m src.webgui --host 0.0.0.0 --port $PORT#" \
        -e "s#^EnvironmentFile=.*#EnvironmentFile=-$PROJECT_DIR/deploy/kpm.env#" \
      deploy/kpm-webgui.service | sudo tee "$UNIT_DIR/$SERVICE.service" >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl enable --now "$SERVICE.service"
    echo "[install] system service started: systemctl status $SERVICE"
  fi
fi

echo "[install] done. Project: $PROJECT_DIR"
