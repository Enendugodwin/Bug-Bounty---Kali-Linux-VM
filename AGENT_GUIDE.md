# 🤖 AI Agent Security Scanning Guide (v2 — Bug-Bounty Workflow)

This framework performs **authorized** security assessments. The intended
workflow is: **read the scope → run a scoped assessment → review the findings
report**.

---

## 🚨 Safety & Compliance (CRITICAL)

- **Authoritative scope**: `scope.yaml` (see below). It is a *deny-by-default*
  allow-list: a target must be listed under `in_scope` **and** must not match
  any `out_of_scope` entry.
- **Never** test a target that is not in scope. Out-of-scope rules always win.
- **Rules of engagement** live in `scope.yaml → rules` (allowed ports/schemes,
  rate limits, intrusive/destructive toggles). Intrusive + destructive testing
  are **off** by default.
- `scope.txt` still works as a minimal legacy fallback if `scope.yaml` is absent.

---

## ⚡ Quickstart (CLI)

```bash
cd ~/kali-pentest-mcp/bugbounty/kali-pentest-mcp
source .venv/bin/activate

python -m src.cli scope                         # show in-scope + exclusions + rules
python -m src.cli scope-check www.example.com   # AUTHORIZED / DENIED + reason
python -m src.cli assess www.example.com --profile web --dry-run   # show the plan only
python -m src.cli assess www.example.com --profile web --operator alice
python -m src.cli assess www.example.com --profile full --deep      # slower, seclists
python -m src.cli report                         # regenerate latest report
python -m src.cli reparse                        # re-derive findings from artifacts (no re-scan)
python -m src.cli enrich                         # fetch body evidence for discovered 200s (redacted)
python -m src.cli cve www.example.com --operator alice   # CVE sweep: nuclei high/critical + nmap vuln
python -m src.cli matrix www.example.com --operator alice # FULL tool matrix (all scanners)
python -m src.cli infra 10.0.0.5 --operator alice          # infra: firewalls/Windows/switches/Linux
python -m src.cli intrusive --url https://host/console --confirm-authorized  # opt-in, non-destructive PoC
python -m src.cli serve                          # run the MCP server (stdio)
python -m src.webgui --port 8080                 # web GUI (live progress bars)
```

For multiple engagements, keep a separate scope file per program and select it
per CLI process without replacing the default:

```bash
KPM_SCOPE_FILE=scope.city-of-vienna.yaml .venv/bin/python -m src.cli scope
KPM_SCOPE_FILE=scope.city-of-vienna.yaml .venv/bin/python -m src.cli assess www.wien.at --profile network
```

Every assessment writes:

```
reports/<target>_<profile>_<timestamp>.md      # review-ready, human readable
reports/<target>_<profile>_<timestamp>.json    # machine readable
artifacts/<target>_<tool>_<...>.txt            # raw tool output (evidence)
logs/audit.log                                 # every command + run id
```

---

## 🗺️ Scope model (`scope.yaml`)

```yaml
program:
  name: "My Bug Bounty Program"
  authorization: "Testing authorized under program rules."
rules:
  max_requests_per_second: 5
  max_concurrency: 10
  allowed_ports: []            # empty = no restriction; e.g. [80, 443]
  allowed_schemes: ["https", "http"]
  allow_intrusive: false       # brute force / exploitation off
  allow_destructive: false
in_scope:
  domains:    [www.example.com]
  wildcards:  ["*.example.com"]   # subdomains only, not the apex
  ips:        [10.0.0.5]
  cidrs:      [10.0.0.0/24]
out_of_scope:
  domains:    [admin.example.com]
  wildcards:  []
  ips:        []
  cidrs:      []
  paths:      ["/logout", "/admin/delete"]
```

`scope-check` output is the ground truth an agent should consult before any
tool call.

For path-based exclusions, the `web` profile filters its Gobuster wordlist and
filters collected endpoints against scope. Nikto is skipped when path
exclusions exist because it cannot reliably guarantee it will avoid them.

---

## 🧠 Assessment profiles

| Profile   | What runs                                                        |
| :-------- | :--------------------------------------------------------------- |
| `web`     | nmap → `httpx` fingerprint → per port: `nikto` + `feroxbuster` (falls back to `gobuster`) |
| `network` | nmap service scan (top 500 ports)                                |
| `full`    | network + web                                                    |

Discovery prefers **`feroxbuster`** (recurses, auto-calibrates soft-404s) and
fingerprints with **`httpx-toolkit`** (ProjectDiscovery) when installed. Add
`--nuclei` to run a nuclei sweep (medium/high/critical, `dos`/`fuzz` excluded)
from the `web` profile; `--deep` enables it too alongside the seclists wordlist.

Defaults are deliberately polite (rate-limited, bounded timeouts, curated
wordlist). Use `--deep` for the full seclists wordlist.

---

## 🛠️ MCP Tool Reference

| Tool | Purpose |
| :--- | :--- |
| `scope_info()` | Show active scope, exclusions, and rules. |
| `scope_check(target)` | AUTHORIZED / DENIED decision before testing. |
| `assess_target(target, profile, operator, dry_run)` | Run the full scoped workflow + write report. |
| `cve_agent(target, severity, latest)` | Scope-limited nuclei CVE scan; Nmap vuln scripts are opt-in. |
| `matrix_agent(target, operator, include_intrusive, confirm_intrusive)` | Full tool matrix; optional intrusive phase requires both flags and scope authorization. |
| `infra_agent(target, operator, include_intrusive, confirm_intrusive)` | Infrastructure scan (firewalls/Windows/switches/Linux), service-driven and scope-enforced. |
| `planner(goal, target, profile)` | Produce a scoped step-by-step plan. |
| `recon_agent(target, options)` | Network recon (nmap; enum4linux on Windows/SMB). |
| `web_agent(target, options)` | Nikto web scan with sane defaults. |
| `ad_agent(target, options, confirm_intrusive)` | AD enumeration — requires explicit confirmation and `allow_intrusive: true`. |
| `run_security_tool(tool, target, options, confirm_intrusive)` | Whitelisted tool; intrusive tools require explicit confirmation and scope authorization. |
| `generate_findings_report()` | Render the latest assessment report as Markdown. |
| `query_past_scans(query)` | RAG search over previous findings. |

---

## 🔎 Findings & reporting

Raw tool output is normalized into findings with **severity, endpoint,
evidence, remediation, and references**. Report sections: authorization,
rules of engagement, summary counts, findings detail, methodology (commands +
exit codes), and a raw-output appendix.

Cross-tool duplicates are merged by CVE or canonical endpoint, retaining the
worst severity and listing all contributing tools. Confidence and validation
status are included so scanner heuristics are not presented as confirmed
vulnerabilities. For example, Wapiti's OpenSSL CCS/CVE-2014-0224 signature is
reported as medium/low-confidence and requires manual validation; a
SearchSploit keyword match is informational until version applicability is
confirmed.

Detection rules are heuristic; always review the evidence. To tune detections
**without re-scanning a target**, use `reparse` — it re-analyses stored
artifacts only (polite and fast).

**Evidence enrichment (`enrich`)**: for every discovered URL that returns
HTTP 200, the framework fetches a bounded body sample, attaches it as evidence,
and classifies it by **content signature** as well as path — e.g. exposed
Werkzeug/Flask debug consoles, Django `DEBUG=True`, `phpinfo()`, directory
listings, and files containing secrets. Severity is promoted accordingly and
**secret values are redacted by default** (env-style `KEY=value`, quoted
`secret`/`token`/`pin`, and `user:pass@host` URLs). This runs automatically in
the `web` profile (`fetch_exposed_files: true`, capped by
`max_evidence_fetches`), or on demand via `python -m src.cli enrich`.

**Validation & false-positive reduction**: after discovery, the `web` profile
re-checks each high-value 200 once (bounded, rate-limited, scope-checked). A
finding whose re-check no longer returns 200 is marked `unconfirmed` and
downgraded; a live 200 confirms it. Findings seen by two or more tools are
marked `scanner_match`. Pure informational noise is dropped. The report carries
a **Confidence & Validation** summary, a derived **CWE** per finding, and an
*Unverified — Needs Manual Validation* section so scanner heuristics are not
read as confirmed.

**CVE intelligence (CVSS/EPSS)**: findings that reference a CVE are enriched
from public intelligence — **EPSS** (FIRST.org, batched by CVE) and **CVSS**
(preferring the scanner's own score, topped up from the **NVD**). Results are
cached in `logs/cveintel.json`, so repeat runs are offline; the module only ever
talks to FIRST.org / NVD, never the target. Set `NVD_API_KEY` for a higher NVD
quota (or `KPM_NVD_ANON=1` for a few anonymous lookups); disable entirely with
`--no-cve-intel`. Reports show CVSS/EPSS per finding plus a **Top Risk (by
EPSS)** section.

## 🛡️ WAF / edge block detection

Before the `web`, `matrix`, and `cve` profiles run any scanner, they send a
single polite probe to the target. If the edge answers with a **block or
challenge page** (Imperva/Incapsula, Cloudflare, Akamai, Sucuri, F5, AWS WAF,
DDoS-Guard, ...), the scan is stopped and marked **INCONCLUSIVE** rather than
reporting the block page's contents as findings:

- `Assessment.scan_status` becomes `inconclusive`, and `Assessment.block`
  records the vendor, HTTP status, and evidence.
- The report shows a prominent banner and a **WAF / Edge Protection** section,
  and no scanner results are emitted.
- As a second line of defence, if a scanner still captures a block-page
  artifact (e.g. nikto reporting header `x-iinfo`), `quarantine_waf_artifacts()`
  moves it out of the findings and notes it under *Scope-safe omissions*.

A normal `200` that merely carries a WAF header (e.g. Cloudflare `cf-ray`) is
**not** treated as blocked. To deliberately scan through the edge, the `assess`
command accepts `--ignore-block`; use it only when you are sure the program
permits testing through its WAF.

## 🔒 Intrusive validation (opt-in)

`src/intrusive.py` validates a vulnerability with a **harmless** probe — by
default it evaluates the Python expression `40+2` (no OS commands, no writes,
no data access). It is triple-gated:

1. the CLI requires `--confirm-authorized`,
2. the target must be in scope, and
3. `scope.yaml → rules.allow_intrusive` must be `true`.

```bash
python -m src.cli intrusive --url https://target/console --confirm-authorized
```

Supported today: exposed **Werkzeug/Flask debug console** (confirms unauthenticated
debugger access, attempts the forwarded-header trust bypass and a bounded PIN
derivation, and reports whether code execution is reproducible). Every attempt
is written to `logs/audit.log`. Set `allow_intrusive: false` again when done.

---

## 🧨 CVE scanning (`cve`)

`src/cve.py` checks the newest CVE templates and sweeps the requested nuclei
severities. Nmap NSE vuln scripts are a separate intrusive opt-in.

```bash
python -m src.cli cve www.example.com --latest 10 --severity high,critical
python -m src.cli cve www.example.com --rate 3 --concurrency 5 --timeout 3600
# Only if the program authorizes intrusive Nmap vuln scripts:
python -m src.cli cve www.example.com --nmap-vuln --confirm-intrusive
```

- `--severity` runs nuclei across all templates with those severities
  (default `high,critical`).
- `--latest N` additionally runs the **N newest CVE templates** (selected by
  CVE id from `~/.local/nuclei-templates`).
- Requested `--rate` and `--concurrency` are **clamped to `scope.yaml` rules**;
  if omitted, the scope limits are used. `--timeout` bounds each phase.
- Targets/ports/schemes come from `scope.yaml`; the scanner does not test a
  disallowed port or scheme. With a port allow-list, only those URLs are sent
  to Nuclei.
- Nmap `--script vuln` is **off by default** because some NSE scripts are
  intrusive. It requires `allow_intrusive: true`, `--nmap-vuln`, and
  `--confirm-intrusive`.
- Results are parsed from nuclei JSONL into findings and rendered in a report
  (`profile=cve`); **secret values are redacted in reports, artifacts, and RAG
  memory** before persistence.

First-time setup: `nuclei -update-templates`.

---

## 🧰 Full tool matrix (`matrix`)

`src/matrix.py` runs **every applicable installed tool** in one pass and
aggregates everything into a single report (`profile=matrix`):

```bash
python -m src.cli matrix www.example.com --operator alice
python -m src.cli matrix www.example.com --wordlist /path/list.txt --rate 20
```

| Phase | Tools |
| :--- | :--- |
| Recon | `whatweb`, `nmap -sV`, `nmap --script vuln`, `dnsrecon`, `dig` |
| Discovery | `gobuster`, `ffuf`, `dirb` (per web base) |
| Web app | `nikto`, `wapiti`, `wpscan` |
| CVE / exploits | `nuclei` (high,critical), `searchsploit` |
| Intrusive (gated) | `sqlmap` — skipped by default; requires `allow_intrusive: true`, `--intrusive`, and `--confirm-intrusive` |

The scope rule alone never starts SQLMap. Explicit confirmation is required
for each CLI/MCP request:

```bash
python -m src.cli matrix www.example.com --intrusive --confirm-intrusive
```

The MCP `matrix_agent` and `run_security_tool` have equivalent per-call
confirmation parameters. `ad_agent`/remote-execution tools use the same
two-part gate. Keep `allow_intrusive: false` unless the program explicitly
allows intrusive testing.

Not-applicable tools (e.g. `enum4linux`/`nxc`/`responder` without SMB, `john`/
`hashcat` without hashes, `openvas`/`gvmd` when the Greenbone daemon is down)
are listed under **Skipped / not applicable** rather than failing silently.
`--timeout` bounds each tool; `--rate` caps requests/second.

---

## 🧱 Infrastructure scanning (`infra`)

`src/infra.py` assesses a single authorized host/IP and picks tools from the
services nmap discovers. Deny-by-default scope and RoE rate limits apply, and
tools that are not installed are reported as *skipped*.

```bash
python -m src.cli infra 10.0.0.5 --operator alice
python -m src.cli infra 10.0.0.5 --intrusive --confirm-intrusive   # gated
```

| Discovered service | Tools |
| :--- | :--- |
| SMB/RPC (135/139/445) | `enum4linux-ng`, `nxc smb` |
| LDAP/AD (389/636) | `nxc ldap` |
| WinRM (5985/5986) | `nxc winrm` |
| RDP (3389) | nmap `rdp-enum-encryption`, `rdp-ntlm-info` |
| SSH (22) | nmap `ssh2-enum-algos`, `ssh-auth-methods`, `ssh-hostkey` |
| NFS/RPC (111/2049) | `showmount` |
| SNMP (161) | `onesixtyone` + `snmpwalk` |
| IKE/IPsec (500/4500) | `ike-scan` |
| TLS mgmt (443/8443/993/995) | `sslscan` |

Credential attacks (`hydra`, `evil-winrm`) and nmap `--script vuln` are **off**
and require `allow_intrusive: true` **and** `--intrusive --confirm-intrusive`.

---

## 🖥️ Web GUI

`src/webgui.py` serves a live scan console (Starlette + uvicorn, already
present via MCP — no new deps):

```bash
python -m src.webgui --host 0.0.0.0 --port 8080
# open http://<kali-ip>:8080/
```

- Choose a target + profile (`matrix` or `cve`) + operator, then **Start scan**.
- **Overall status bar** (% and `X/Y steps`) plus a **per-tool progress bar**,
  status badge, duration, exit code and findings-added count for every step.
- **Agent column** — each tool step shows which specialized agent owns it
  (Recon / Web / CVE / Exploit Agent), and the header shows the lead agent.
- **Auto-attach / external detection** — on load (and every few seconds) the
  console detects any running scan and shows it, **including scanner processes
  started outside the GUI** (e.g. from the CLI or an MCP client); the header
  shows a `● N RUNNING` indicator.
- **Persistent jobs** — orchestrated CLI, MCP, and GUI scans publish progress to
  SQLite at `logs/jobs.sqlite3`; jobs/history survive GUI restarts. The GUI
  marks jobs interrupted if their owning scan process exited unexpectedly.
  Standalone raw scanner processes are still detected as a limited fallback.
- Live findings summary and a link to the Markdown report.
- **Scope editor** — view, edit and **save `scope.yaml`** (validated + auto-reloaded),
  plus an inline *scope check* for any target.
- **Report downloads** — download the finished report (`.md` and `.json`) straight
  from the console, and a **Recent reports** list for any report on the server.
- Scans run in background threads; the UI polls `/api/scan/{id}` once a second.
- Endpoints: `POST /api/scan`, `GET /api/scan/{id}`, `GET /api/scan/{id}/report`,
  `GET /api/scan/{id}/download`, `GET /api/scope`, `GET /api/scope/raw`,
  `POST /api/scope/save`, `GET /api/scope/check`, `GET /api/reports`,
  `GET /api/reports/download`.
- Progress comes from events emitted by the orchestrators
  (`scan_start → plan → step_start/step_end → scan_done`).

---

## 🚀 Deployment

See [`deploy/README.md`](deploy/README.md). Quick options:

```bash
deploy/install.sh --check     # report missing scanner tools (no changes)
deploy/install.sh             # .venv + deps + seed scope.yaml
deploy/install.sh --user      # user systemd service for the web GUI (no sudo)
deploy/install.sh --system    # system systemd service (needs sudo)
```

A container image and compose file are included (`Dockerfile`,
`docker-compose.yml`) for hosts with Docker; the MCP server runs over stdio
(`python -m src.server`). The web GUI has **no authentication** — bind it to
`127.0.0.1` or firewall it.

---

## 🧬 Memory & RAG

Every tool result is stored in `memory.pkl`. Use `query_past_scans` to find
similar prior findings across targets (e.g. "open port 8080", "SQL injection").
The store is bounded (`KPM_MEMORY_MAX_DOCS`, default 2000) and saved atomically.

---

## 📁 Project structure

- `src/server.py` — MCP server, agents, tools.
- `src/assess.py` — scope-enforced orchestrator (`run_assessment`, `reparse`).
- `src/cve.py` — CVE scanning (nuclei templates + nmap vuln scripts).
- `src/matrix.py` — full tool-matrix scan (all applicable tools).
- `src/jobs.py` — SQLite-backed cross-process scan status/history.
- `src/intrusive.py` — opt-in, non-destructive intrusive validation.
- `src/webgui.py` — web GUI (live progress + status bars).
- `src/scope.py` — scope loading + deny-by-default decision engine.
- `src/findings.py` — tool-output parsers + severity heuristics.
- `src/report.py` — Markdown/JSON report rendering (`Assessment` model).
- `src/runner.py` — subprocess executor (rate limit, timeout, audit, artifacts).
- `src/memory.py` — TF-IDF RAG vector store.
- `src/cli.py` — command-line interface.
- `scope.yaml` — authorized scope + rules (authoritative).
- `wordlists/web-small.txt` — curated default discovery list.
- `reports/`, `artifacts/`, `logs/` — outputs.

---

## ➕ Extending

- **New detection**: add a `parse_<tool>()` in `src/findings.py` and register it
  in `_PARSERS`.
- **New tool**: add it to the relevant list in `AGENT_TOOLS` (`src/server.py`).
- **New profile**: extend the branch logic in `src/assess.py`.
