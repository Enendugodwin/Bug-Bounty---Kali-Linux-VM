# Project Plan — Deferred Work

Items we deliberately decided to do **later**. Each is self-contained so it can
be picked up cold. Status of the framework itself lives in `README.md` /
`AGENT_GUIDE.md`.

---

## ✅ Done (for context)

- **Speed pass on `assess.py` / `cli.py`** — the `web` profile no longer spends
  ~25 min per run. Changes:
  - nmap scans a curated web-port set (80/443/8080/8443/8000/8888) with
    `--version-light --max-retries 2 --host-timeout 90s` (268s → ~16s).
  - Only 80/443 are scanned when they are open (was 4 ports behind Cloudflare).
  - nikto is bounded with `-maxtime` (default 120s) instead of a 300s timeout.
  - Per-port scans run in parallel (`ThreadPoolExecutor`).
  - New flags: `--all-ports`, `--nikto-maxtime SECONDS`; env: `PENTEST_NIKTO_MAXTIME`,
    `PENTEST_NIKTO_TIMEOUT`, `PENTEST_NMAP_HOST_TIMEOUT`, `PENTEST_NMAP_MAX_RETRIES`,
    `PENTEST_WEB_WORKERS`.
  - Measured: 143s default, 85s with `--nikto-maxtime 45` (was ~25 min).
  - Backups: `src/assess.py.pre-speed.bak`, `src/cli.py.pre-speed.bak`.

---

## 📱 Mobile access to OpenCode sessions (LATER — requested)

Goal: open these agent sessions from a phone.

Key facts (OpenCode V2):
- The server that runs sessions also serves a **password-protected web UI**.
- **V2 has no session-sharing links** — phone access means connecting to the
  whole server, not publicizing a single chat.
- Pairing link is **single-use and expires in 5 minutes**; web sessions last 30 days.
- Server defaults to `localhost:49374`.

### A. Same network (LAN/Wi-Fi)
1. Bind to all interfaces (Windows host):
   ```powershell
   opencode service set hostname 0.0.0.0
   opencode service set port 49374
   opencode service set password "a-long-secret"
   opencode service start
   ```
2. Allow inbound TCP 49374 through Windows Firewall (private network only).
3. Pair: `opencode pair` → scan the QR with the OpenCode app, or open the link
   in the phone browser.
4. If the printed link says `127.0.0.1`, substitute the PC's LAN IP
   (`ipconfig`): `http://<PC-LAN-IP>:49374/...`.

### B. From anywhere (preferred — do NOT expose 49374 to the internet)
- Install **Tailscale/WireGuard** on phone + host, then pair over the tunnel IP.
- Or SSH tunnel from the phone: `ssh -L 49374:127.0.0.1:49374 <user>@<host>`.

### C. Alternative: run the server on the always-on Kali VM
```bash
opencode serve --hostname 0.0.0.0 --port 4096
# then connect other clients with: opencode --server http://<host>:4096
```

### Security notes
- Bind `0.0.0.0` only on trusted networks; prefer a VPN.
- Set a strong server password; changing it signs out all existing web sessions.
- Treat the QR/link as a credential.

---

## 🔗 Bug bounty platform integration (LATER)

Goal: let the agent **read in-scope targets from the platforms you use**, so
`scope.yaml` can be synced instead of hand-copied. Submission stays manual.

### Principles (non-negotiable)
- **Read-only by default.** Scope ingestion only; no autonomous report submission.
- **Human-in-the-loop.** The researcher verifies/reproduces every finding before
  submitting. (Bugcrowd's AI policy: *"Automated or unverified outputs are not
  accepted as valid submissions"*; researchers remain fully accountable.)
- **Secrets in env, never committed.** Tokens live in the environment, not in
  `opencode.jsonc` / repo files. Synced scope is confidential (private/NDA
  programs) — **never commit a synced `scope.yaml`**.
- **Respect rate limits** and keep `rules.max_requests_per_second` well under
  each platform's API cap.

### Platform matrix (verify access before relying on any row)
| Platform | Auth | Scope sync | Submit report | Notes |
| --- | --- | --- | --- | --- |
| **Bugcrowd** | API 1.1.0, per-user token, `Authorization: Token <t>` | ✅ `/programs` + briefs → target groups/targets | ❌ no researcher submit endpoint (web form / email) | 60 req/min/IP, IPv4 only, optional IP allowlist; token is role-scoped |
| **HackerOne** | Hacker API, HTTP Basic `username:token` | ✅ structured scopes + scope exclusions | ✅ `create report` endpoint exists | read 600/min, write 25/20s, structured scopes 50/min; `severity_rating` required by many programs |
| **Intigriti** | direct API — *verify* | via aggregator, or direct if access allows | manual | — |
| **YesWeHack** | direct API — *verify* | via aggregator | manual | — |
| **Federacy / HackenProof / others** | via aggregator | ✅ (JSON dumps) | manual | — |
| **Universal fallback** | none | ✅ [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) — hourly-updated dumps for HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy, HackenProof | — | no auth; check program rules (wildcards vs. exclusions) |

### Design
- `src/platforms/` package with a common interface and one adapter per platform:
  - `list_programs()`
  - `get_scope(program) -> {domains, wildcards, ips, cidrs, exclusions, notes}`
  - `merge_into_scope_yaml(...)` — **preserve existing `rules`**, only update the
    `in_scope` / `out_of_scope` allow-lists.
- Adapters: `bugcrowd.py`, `hackerone.py`, `aggregator.py` (bounty-targets-data).
- CLI: `python -m src.cli platform-sync <platform> <program> [--merge]`.
- MCP tool: `platform_scope(platform, program)` so the agent can pull scope on demand.
- Config: `BUGCROWD_TOKEN`; `HACKERONE_USERNAME` + `HACKERONE_TOKEN`; documented in
  `.env.example`.
- **No submit tool by default.** If one is ever added, gate it like the existing
  `intrusive` workflow (explicit `--confirm-authorized` + human approval) so the
  agent can never autonomously file a report.

### Caveats
- Some engagements require Bugcrowd's **Cloudflare Zero Trust / WARP** client
  before targets are reachable.
- Private program scope is under NDA — keep the repo private and exclude
  `scope.yaml` (already planned in `.gitignore`).
- Verify what a **researcher** token can actually read (the Bugcrowd API is
  written primarily for customer/org workflows); don't assume write endpoints.

### Tasks
- [ ] Token storage + `.env.example` documentation.
- [ ] Bugcrowd adapter — confirm researcher token can read `/programs`.
- [ ] HackerOne adapter (structured scopes).
- [ ] Aggregator fallback (`bounty-targets-data`) for platforms without easy API access.
- [ ] `scope.yaml` merge that preserves `rules`; unit tests.
- [ ] MCP `platform_scope` tool aligned with the existing scope-enforcement model.

---

## 📦 Publish to GitHub (LATER)

Currently **not a git repo** and intentionally kept private until setup files
are shareable. When ready:

- [ ] `git init` and set identity (`user.name` / `user.email`).
- [ ] Fill `.gitignore`: `.venv/`, `__pycache__/`, `artifacts/`, `reports/`,
      `logs/`, `memory.pkl`, `scope.yaml`, `scope.txt`, `*.pre-speed.bak`.
- [ ] Scrub live target data from `scope.yaml` (keep `scope.yaml.example`).
- [ ] Fill `.env.example` with the `PENTEST_*` knobs.
- [ ] Confirm `requirements.txt` installs cleanly in a fresh venv.
- [ ] Add `LICENSE`; proofread `README.md` / `AGENT_GUIDE.md` / `capabilities.md`.
- [ ] Create a **private** repo, push, then add CI (pytest/ruff/bandit).

## 💻 Cross-device install (LATER)

Full procedure discussed. Short version — target device is Linux/Kali, and the
layout `$HOME/kali-pentest-mcp/bugbounty/kali-pentest-mcp` is hardcoded in
`bootstrap.sh` / `mcp_smoke_test.py`:

1. `sudo apt install -y python3 python3-venv python3-pip git nmap nikto gobuster`
   (plus optional matrix/CVE tools).
2. Copy the source (exclude `.venv`, `artifacts`, `reports`, `logs`, `memory.pkl`,
   real `scope.yaml`), or `git clone` once it's published.
3. `bash bootstrap.sh` (venv + deps + seeds scope files).
4. Edit `scope.yaml` with the authorized target.
5. Verify: `python -m src.cli scope`, `python -m src.cli assess <t> --dry-run`,
   `python mcp_smoke_test.py`.
6. Register the stdio MCP server in OpenCode (`mcp.servers.kali-pentest`,
   `type: "local"`, `command` = venv python `-m src.server`, plus `cwd`).

## 🧹 Gaps & cleanup (LATER)

- [ ] `AGENT_GUIDE.md` documents an `enrich` command / `src/enrich.py` that does
      **not exist**. Either implement it or remove the docs.
- [ ] Make `bootstrap.sh` path-independent instead of assuming the fixed layout.
- [ ] Decide whether `cve.py` / `matrix.py` / `intrusive.py` CLI subcommands are
      fully wired (guide lists them; verify against `cli.py`).
