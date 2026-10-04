# 🛠️ Project Capabilities: AI-Native Security Framework

An AI-driven, **scope-enforced** security assessment framework on Kali Linux.
It turns a standard pentest toolset into an orchestrated system an AI agent (or
a human via CLI/GUI) can plan, execute, and remember — for **authorized**
bug-bounty / challenge targets only.

> ⚠️ Deny-by-default. Only targets in `scope.yaml` (or legacy `scope.txt`) are
> ever touched.

---

## 🌟 Core Capabilities

### 1. 🛡️ Scope-Enforced Execution
A strict authorization boundary. `scope.yaml` defines in-scope domains,
`*.wildcards`, IPs, CIDRs, **out-of-scope exclusions (which always win)**,
excluded paths, allowed ports/schemes and rules of engagement. Every tool call
passes the scope gate first; out-of-scope targets are refused before execution.

### 2. 🧠 Multi-Agent Orchestration
- **Planner** — scope-aware, step-by-step plan for a goal.
- **Recon Agent** — `nmap` (+ `enum4linux` on Windows/SMB).
- **Web Agent** — `nikto` baseline.
- **AD Agent** — gated behind `allow_intrusive`.
- **`assess_target`** — full recon → web → findings → report workflow.
- **`cve_agent`** — scope-limited nuclei CVE coverage (Nmap vuln scripts are opt-in).
- **`matrix_agent`** — the *full* tool matrix in one pass.

### 3. 🧰 Full Toolset Integration
- **Recon**: `nmap` (`-sV`, `--script vuln`), `whatweb`, `dnsrecon`, `dig`, `enum4linux`.
- **Discovery**: `gobuster`, `ffuf`, `dirb`.
- **Web app**: `nikto`, `wapiti`, `wpscan`.
- **CVE / exploits**: `nuclei` (scope-clamped severity sweep + newest-N CVE templates), `searchsploit`.
- **Intrusive (explicitly gated)**: `sqlmap`; AD/remote-execution tools
  `nxc`/`netexec`/`impacket` require scope authorization **and a per-request
  confirmation**. Matrix scans skip SQLMap by default.
- **Cracking**: `john`, `hashcat`.
- Not-applicable tools are reported as *skipped* rather than failing silently.

### 4. 📝 Findings Normalization & Reporting
Raw output is parsed into findings with **severity, endpoint, description,
evidence, remediation and references**. Reports are written as **Markdown +
JSON** (`reports/<target>_<profile>_<ts>.md|.json`) with: authorization, rules
of engagement, severity summary, per-finding detail, methodology (commands +
exit codes) and a raw-output appendix.
Cross-tool duplicates merge by CVE or endpoint and retain all source tools;
confidence/validation status distinguish scanner matches from verified issues.
Wapiti's OpenSSL CCS heuristic is downgraded to medium/low-confidence pending
manual validation; SearchSploit keyword matches are informational until the
affected version is confirmed.

### 5. 🔎 Evidence Enrichment & Redaction
For discovered URLs that return HTTP 200, the framework fetches a bounded body
sample, attaches it as evidence, and classifies by **content signature** as well
as path — exposed `.env` secrets, **Werkzeug/Flask debug consoles**, Django
`DEBUG=True`, `phpinfo()`, directory listings, etc. Severity is promoted and
**secret values are redacted by default** (env `KEY=value`, quoted
`secret`/`token`/`pin`, and `user:pass@host` URLs).

### 6. 🔒 Intrusive Validation (opt-in)
`src/intrusive.py` proves vulnerabilities with a **harmless** probe (default
`40+2`, no OS commands / writes / data access). Triple-gated: explicit
`--confirm-authorized`, in-scope target, and `allow_intrusive: true`.

### 7. 🖥️ Web GUI — Live Progress, Scope Editor & Downloads
`src/webgui.py` (Starlette + uvicorn) serves a cyber-styled console with an
**overall status bar** and **per-tool progress bars**, status badges, durations,
exit codes, findings counts and report links. Each step shows the **agent in
charge** (Recon / Web / CVE / Exploit Agent), and the console **auto-attaches to
any running scan** — including scanner processes started outside the GUI, such as
from the CLI — so progress is visible from any browser. It also provides a
**scope editor** (view / validate / save `scope.yaml`, live scope-check) and
**report downloads** (per-scan `.md`/`.json` plus a recent-reports list). Scans
run in background threads and stream progress via events.
Open `http://<kali-ip>:8080/`.

### 8. 📚 RAG-Powered Security Memory
Every tool result is vectorized into `memory.pkl`. Query past scans for patterns
across targets (`query_past_scans`). The store is bounded and saved atomically.

### 9. 🧾 Audit Trail
Every executed command (and intrusive attempt) is appended to `logs/audit.log`
with a run id; raw tool output is preserved under `artifacts/`.

### 10. 📈 Persistent Scan Jobs
CLI, MCP, and GUI orchestrators publish plans, per-tool status, elapsed time,
findings counts, and report paths to `logs/jobs.sqlite3`. The GUI can resume
displaying job status after a restart and marks jobs interrupted if their owner
process exited before completion. Standalone scanner processes remain a
best-effort fallback.

### 11. 🧱 WAF Detection & Origin Exposure
`waf_check` fingerprints the WAF in front of an authorized target (`wafw00f`
plus header/cookie signatures: Cloudflare, Imperva Incapsula, Akamai, F5,
Sucuri, AWS, ModSecurity, …) and raises two flags: **no WAF in place**, and an
**origin IP directly reachable** — which would mean the WAF can likely be
bypassed by targeting the origin. The resolved IP is always reported, but the
origin probe only runs when that IP is explicitly listed in `scope.yaml`
(`ips:`/`cidrs:`); a domain in scope never auto-authorizes its IP.

---

## 💬 Prompt Examples for the AI Agent

- *"Use the **planner** for `www.example.com`, then **assess_target** and show me the findings."*
- *"Run **cve_agent** on the target for high/critical CVEs plus the 10 newest CVE templates."*
- *"Run **matrix_agent** — I want every applicable tool used."*
- *"Use **query_past_scans** to see if we've seen this header pattern before."*
- *"Open the GUI so I can watch each tool's progress."*

---

## 🧭 Interfaces

- **CLI** (`python -m src.cli`): `scope`, `scope-check`, `assess`, `report`,
  `reparse`, `enrich`, `cve`, `matrix`, `intrusive`, `serve`.
- **GUI**: `python -m src.webgui --host 0.0.0.0 --port 8080`.
- **MCP server** (`python -m src.cli serve`): 13 tools —
  `scope_info`, `scope_check`, `assess_target`, `cve_agent`, `matrix_agent`,
  `planner`, `recon_agent`, `web_agent`, `ad_agent`, `run_security_tool`,
  `waf_check`, `generate_findings_report`, `query_past_scans`.

---

## 📁 Project Architecture
- `src/server.py` → MCP tools / agents
- `src/cli.py` → command-line interface
- `src/assess.py` → scoped assessment orchestrator (+ reparse)
- `src/cve.py` → CVE scanning (nuclei + nmap vuln)
- `src/matrix.py` → full tool-matrix scan
- `src/intrusive.py` → opt-in non-destructive validation
- `src/webgui.py` → web GUI (live progress)
- `src/jobs.py` → persistent cross-process scan history/status (SQLite)
- `src/scope.py` → authorization / deny-by-default engine
- `src/waf.py` → WAF detection / origin-exposure checks (scope-gated)
- `src/findings.py` → output parsers + severity heuristics
- `src/report.py` → Markdown/JSON reporting
- `src/runner.py` → safe execution (rate limit, timeout, audit, artifacts)
- `src/memory.py` → RAG vector store
- `scope.yaml` → authorized scope + rules (authoritative; `scope.txt` fallback)
