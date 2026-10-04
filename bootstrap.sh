#!/bin/bash
PROJECT_DIR="$HOME/kali-pentest-mcp/bugbounty/kali-pentest-mcp"
mkdir -p "$PROJECT_DIR" && cd "$PROJECT_DIR"

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# Seed scope files if they do not exist yet.
if [ ! -f scope.yaml ] && [ -f scope.yaml.example ]; then
    cp scope.yaml.example scope.yaml
    echo "[bootstrap] created scope.yaml from template — EDIT IT before scanning."
fi
if [ ! -f scope.txt ] && [ -f scope.txt.example ]; then
    cp scope.txt.example scope.txt
fi
