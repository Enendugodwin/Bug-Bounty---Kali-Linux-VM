# Kali Pentest MCP

An AI-native, **scope-enforced** security assessment framework for Kali Linux.
Point it at an authorized bug-bounty target and it will: verify scope → run a
polite assessment → produce a review-ready findings report (Markdown + JSON).

> ⚠️ Use only against targets you are explicitly authorized to test. The
> authoritative allow-list is `scope.yaml`; testing is deny-by-default.

## Install

```bash
bash bootstrap.sh          # creates .venv, installs deps, seeds scope files
source .venv/bin/activate
```

For services and containers see [`deploy/README.md`](deploy/README.md)
(`deploy/install.sh --user` sets up a systemd web-GUI service; a `Dockerfile`
and `docker-compose.yml` are included).

## Usage

```bash
python -m src.cli scope                                   # what's authorized
python -m src.cli scope-check www.example.com             # AUTHORIZED / DENIED
KPM_SCOPE_FILE=scope.city-of-vienna.yaml python -m src.cli scope # select a separate engagement scope
python -m src.cli assess www.example.com --profile web --dry-run
python -m src.cli assess www.example.com --profile web --operator alice
python -m src.cli report        # regenerate latest report
python -m src.cli reparse       # re-derive findings from artifacts (no re-scan)
python -m src.cli cve www.example.com --latest 10 --severity high,critical # scope-clamped nuclei CVE sweep
python -m src.cli matrix www.example.com # FULL tool matrix (all scanners)
python -m src.cli matrix www.example.com --intrusive --confirm-intrusive # explicit opt-in SQLMap
python -m src.cli serve         # run the MCP server
python -m src.webgui --port 8080 # web GUI (live progress + status bars)
```

The GUI (open `http://<kali-ip>:8080/`) shows an overall status bar and a
per-tool progress bar/status for each scan step, auto-attaches to any running
scan, and lets you **view/edit `scope.yaml`** and **download finished reports**
(`.md`/`.json`).

Outputs:

- `reports/<target>_<profile>_<ts>.md` / `.json`
- `artifacts/*.txt` (raw evidence)
- `logs/audit.log`

See [`AGENT_GUIDE.md`](AGENT_GUIDE.md) for the full workflow, scope schema,
profiles, MCP tools, and extension points, and
[`capabilities.md`](capabilities.md) for the capability overview.

## Profiles

| Profile | Tools |
| --- | --- |
| `web` | nmap → httpx fingerprint → nikto → feroxbuster (gobuster fallback); `--nuclei` adds a nuclei sweep |
| `network` | nmap service scan |
| `full` | network + web |
| `cve` | nuclei (high/critical + newest CVEs) + nmap vuln |
| `infra` | service-driven: SMB/AD, SSH, SNMP, RDP, NFS, IKE/VPN, TLS (`src/infra.py`) |

## Architecture

`server.py` (MCP tools) · `cli.py` (CLI) · `webgui.py` (GUI) ·
`assess.py` (orchestrator) · `cve.py` (CVE scanning) · `matrix.py` (all tools) ·
`infra.py` (firewalls/Windows/switches/Linux) · `cveintel.py` (CVSS/EPSS) ·
`intrusive.py` (opt-in PoC) · `scope.py` (authz) · `findings.py` (parsers) ·
`report.py` (reporting) · `jobs.py` (persistent scan history) ·
`runner.py` (safe exec) · `memory.py` (RAG).
