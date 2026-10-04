# syntax=docker/dockerfile:1
#
# Kali Pentest MCP — container image.
#
# Based on Kali Linux because the framework orchestrates Kali's own tooling
# (nmap, nikto, feroxbuster, nuclei, sqlmap, ...). The image is intentionally
# large — the scanners are the point.
#
# Scope is deny-by-default. Mount your authoritative allow-list at
# /app/scope.yaml (see docker-compose.yml).
#
# Build:
#   docker build -t kali-pentest-mcp:latest .
# Run the MCP server over stdio (for an MCP client):
#   docker run -i --rm --network host \
#     -v "$PWD/scope.yaml:/app/scope.yaml" kali-pentest-mcp:latest
# Run the web GUI:
#   docker run --rm --network host \
#     -v "$PWD/scope.yaml:/app/scope.yaml" \
#     -v "$PWD/reports:/app/reports" \
#     kali-pentest-mcp:latest python -m src.webgui --host 0.0.0.0 --port 8080

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH" \
    KPM_SCOPE_FILE=/app/scope.yaml

# Core scanners available from the Kali repositories.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        ca-certificates curl \
        nmap nikto gobuster ffuf dirb whatweb wafw00f dnsrecon \
        sqlmap wpscan wapiti \
    && rm -rf /var/lib/apt/lists/*

# Optional / newer scanners. Install best-effort so an unavailable package in
# a given Kali snapshot does not fail the build.
RUN apt-get update && (apt-get install -y --no-install-recommends \
        nuclei feroxbuster httpx-toolkit \
        || echo "[image] optional scanners unavailable in this Kali snapshot") \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies first for better layer caching.
COPY requirements.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt

COPY . .

# Scan output — mount these to keep results on the host.
VOLUME ["/app/reports", "/app/artifacts", "/app/logs"]

# Default to the MCP server over stdio; override for the web GUI.
CMD ["python", "-m", "src.server"]
