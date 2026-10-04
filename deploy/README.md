# Kali Pentest MCP — Deployment

Three ways to run the framework, in order of how much they assume:

1. **Direct** — Python venv on the host (Kali).
2. **systemd** — run the web GUI as a service.
3. **Docker** — container image for another host.

> ⚠️ Scope is **deny-by-default**. Every deployment needs an authoritative
> `scope.yaml`. Never point it at a target you are not authorized to test.

---

## 1. Direct install

```bash
cd /home/AIuser/kali-pentest-mcp/bugbounty/kali-pentest-mcp
deploy/install.sh --check     # report missing scanner tools
deploy/install.sh             # create .venv, install deps, seed scope.yaml
deploy/install.sh --tools     # apt-get the missing scanners (needs sudo)
```

Then edit `scope.yaml`, and run:

```bash
.venv/bin/python -m src.cli scope
.venv/bin/python -m src.cli assess www.example.com --profile web
.venv/bin/python -m src.webgui --host 127.0.0.1 --port 8080
```

---

## 2. systemd service (web GUI)

`deploy/install.sh --user` installs a **user** service (no sudo):

```bash
deploy/install.sh --user --port 8080
systemctl --user status kpm-webgui
journalctl --user -u kpm-webgui -f
loginctl enable-linger "$USER"   # optional: run without an active login
```

`deploy/install.sh --system` installs a **system** service (needs sudo):

```bash
sudo deploy/install.sh --system --port 8080
systemctl status kpm-webgui
```

Both read optional settings from `deploy/kpm.env` (copy `kpm.env.example`).
To run the **MCP server** instead of the GUI, override `ExecStart` with
`... -m src.server` — but note stdio MCP servers are normally launched by the
MCP client, not by systemd.

---

## 3. Docker / Compose

Build and run:

```bash
docker build -t kali-pentest-mcp:latest .

# MCP server over stdio (for an MCP client):
docker run -i --rm --network host \
  -v "$PWD/scope.yaml:/app/scope.yaml" kali-pentest-mcp:latest

# Web GUI:
docker run --rm --network host \
  -v "$PWD/scope.yaml:/app/scope.yaml" \
  -v "$PWD/reports:/app/reports" \
  kali-pentest-mcp:latest python -m src.webgui --host 0.0.0.0 --port 8080
```

Compose:

```bash
docker compose up -d --build webgui      # http://<host>:8080
docker compose run --rm -T mcp           # MCP stdio, per client
```

The image is **large** (Kali + scanners) and `network_mode: host` is used so
scans can reach the network and the GUI can bind `:8080`.

### MCP client configuration

Claude Desktop / any MCP client (stdio transport):

```json
{
  "mcpServers": {
    "kali-pentest": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "host",
               "-v", "/home/AIuser/kali-pentest-mcp/bugbounty/kali-pentest-mcp/scope.yaml:/app/scope.yaml",
               "-v", "/home/AIuser/kali-pentest-mcp/bugbounty/kali-pentest-mcp/reports:/app/reports",
               "kali-pentest-mcp:latest",
               "python", "-m", "src.server"]
    }
  }
}
```

Without Docker, point `command` at the venv and `cwd` at the project:

```json
{
  "mcpServers": {
    "kali-pentest": {
      "command": "/home/AIuser/kali-pentest-mcp/bugbounty/kali-pentest-mcp/.venv/bin/python",
      "args": ["-m", "src.server"],
      "cwd": "/home/AIuser/kali-pentest-mcp/bugbounty/kali-pentest-mcp"
    }
  }
}
```

---

## Security notes

- **The web GUI has no authentication.** Do not expose port 8080 to untrusted
  networks. Bind it to `127.0.0.1` (`--host 127.0.0.1`) and reach it over an SSH
  tunnel, or firewall it. It can edit `scope.yaml` and start scans.
- **Scope is the only authorization boundary.** Keep `scope.yaml` accurate and
  never add a target you are not authorized to test.
- Scanner binaries run with the service user's privileges. Some nmap modes
  benefit from root, but the default service runs unprivileged on purpose.
- The container talks to the network to scan; only mount the scope file and
  output directories you intend to share.
