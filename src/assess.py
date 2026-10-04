"""Scope-enforced assessment orchestrator.

``run_assessment`` is the single entry point used by both the CLI and the
MCP server. It:

1. hard-verifies the target against the active scope (deny-by-default),
2. runs a profile-appropriate tool chain,
3. captures every command as an artifact + audit entry,
4. parses output into normalized findings,
5. stores results in RAG memory,
6. writes a Markdown + JSON report.

Performance notes
-----------------
Earlier versions scanned *every* http-ish port nmap reported and gave nikto a
300s subprocess timeout on each, one port at a time. Against a CDN-fronted
target that meant 4 sequential nikto runs, each hitting the timeout — ~25
minutes for little signal. The chain now:

* scans a small, curated set of web ports for the web profile instead of a
  100-port sweep (most of which are filtered and cost ~4 min of retries),
* prefers the canonical web ports (80/443) when they are open,
* bounds nikto with ``-maxtime`` so a WAF cannot eat the whole timeout,
* runs the independent per-port scans concurrently.
"""

from __future__ import annotations

import logging
import math
import os
import re
import shlex
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from . import findings as findings_mod
from . import jobs, memory, report as report_mod, runner, scope

log = logging.getLogger("kpm.assess")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUNDLED_WORDLIST = PROJECT_ROOT / "wordlists" / "web-small.txt"
SECLISTS_COMMON = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

# Ports that almost always front the real application. When one of these is
# open we scan only them, instead of every http-ish port nmap reports (which,
# behind a CDN, can mean several near-identical 5-minute nikto runs).
CANONICAL_WEB_PORTS = [80, 443]

# nmap target set for the web profile. A short explicit list is far faster than
# ``-F`` on a filtered host (nmap otherwise waits out retries on ~95 ports).
WEB_PROFILE_PORTS = [80, 443, 8080, 8443, 8000, 8888]

# Bound nikto so a CDN/WAF that black-holes probes cannot burn the full
# subprocess timeout on every port.
NIKTO_MAXTIME = int(os.getenv("PENTEST_NIKTO_MAXTIME", "120"))
NIKTO_TIMEOUT = int(os.getenv("PENTEST_NIKTO_TIMEOUT", str(NIKTO_MAXTIME + 30)))

# nmap spends most of its time waiting on filtered ports; cap the host.
NMAP_HOST_TIMEOUT = os.getenv("PENTEST_NMAP_HOST_TIMEOUT", "90s")
NMAP_MAX_RETRIES = os.getenv("PENTEST_NMAP_MAX_RETRIES", "2")

# How many discovered web ports to scan in parallel.
WEB_WORKERS = int(os.getenv("PENTEST_WEB_WORKERS", "4"))

# nmap -sV output: "443/tcp open  ssl/https"
_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _open_tcp(stdout: str) -> list[tuple[int, str]]:
    return [(int(p), s.lower()) for p, s in _PORT_RE.findall(stdout or "")]


def _base_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    if port in (80, 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _safe(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "target"


# ---------------------------------------------------------------------------
# Exposed-file evidence enrichment
# ---------------------------------------------------------------------------
# When discovery finds a high-value file that is publicly readable, fetch a
# bounded sample of its body and attach it as evidence (secret values
# redacted). This never runs against an out-of-scope target.

_EXPOSED_PATTERNS = [
    (re.compile(r"/\.env(?:\.|/|$|\?)", re.I), "Exposed .env file (secrets)", "critical"),
    (re.compile(r"/\.git/(HEAD|config|index)$", re.I), "Exposed .git repository metadata", "high"),
    (re.compile(r"/\.svn/entries$", re.I), "Exposed .svn metadata", "high"),
    (re.compile(r"/web\.config$", re.I), "Exposed web.config", "high"),
    (re.compile(r"/\.htaccess$", re.I), "Exposed .htaccess", "low"),
    (re.compile(r"/(backup|dump|db|database)[^/]*\.(zip|tar\.gz|tgz|sql|bak|old)$", re.I),
     "Exposed backup/dump file", "high"),
    (re.compile(r"/phpinfo\.php$", re.I), "Exposed phpinfo()", "medium"),
    (re.compile(r"/(config|configuration|settings)\.php$", re.I), "Exposed config file", "high"),
    (re.compile(r"/actuator/(env|heapdump|configprops)$", re.I),
     "Exposed Spring actuator endpoint", "critical"),
    (re.compile(r"/server-status$", re.I), "Exposed Apache server-status", "medium"),
]

_STATUS_RE = re.compile(r"\(Status:\s*(\d+)\)", re.I)

_RANK = {s: i for i, s in enumerate(findings_mod.SEVERITIES)}

_SECRET_LINE_RE = re.compile(
    r"(?im)^([A-Z0-9_.]*(?:SECRET|PASSWORD|PASSWD|PASS|TOKEN|APIKEY|API_KEY|KEY"
    r"|CREDENTIAL|PRIVATE)[A-Z0-9_.]*)[ \t]*=[ \t]*(.+?)[ \t]*$"
)
_URL_CRED_RE = re.compile(r"(\w+://)([^:/@\s]*):([^@/\s]+)@")
_QUOTED_SECRET_RE = re.compile(
    r"(?i)(\b(?:secret|token|api[_-]?key|password|passwd|pin)\b\s*[:=]\s*)"
    r"([\"'])([^\"']+)(\2)"
)


def redact_secrets(text: str) -> str:
    """Mask obvious secret values so evidence can be shared safely."""
    def _mask(val: str) -> str:
        val = val.strip().strip('"').strip("'")
        return "****" if len(val) <= 4 else f"{val[:2]}…{val[-2:]} [{len(val)} chars]"

    def _line(m: re.Match) -> str:
        return f"{m.group(1)}={_mask(m.group(2))}  # REDACTED"

    def _quoted(m: re.Match) -> str:
        return f"{m.group(1)}{m.group(2)}{_mask(m.group(3))}{m.group(4)}"

    out = _SECRET_LINE_RE.sub(_line, text or "")
    out = _QUOTED_SECRET_RE.sub(_quoted, out)
    return _URL_CRED_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}:****@", out)


def _snippet(body: str, limit: int = 400) -> str:
    body = (body or "").strip()
    return body[:limit] + ("\n...[truncated]" if len(body) > limit else "")


def _classify_body(body: str, ctype: str) -> tuple[str, str] | None:
    """Detect high-value content signatures in a fetched response body."""
    low = (body or "").lower()
    if any(sig in low for sig in (
        "werkzeug debugger", "console locked", "__debugger__", "traceback (most recent call last)"
    )):
        return ("Exposed Werkzeug/Flask debug console (potential RCE)", "critical")
    if "debug = true" in low and "you're seeing this error" in low:
        return ("Django debug page (DEBUG=True)", "high")
    if "phpinfo()" in low:
        return ("Exposed phpinfo()", "medium")
    if re.search(r"<title>\s*index of /", low) or "<h1>index of" in low:
        return ("Directory listing enabled", "medium")
    if _SECRET_LINE_RE.search(body or "") or _QUOTED_SECRET_RE.search(body or ""):
        return ("Exposed file containing secrets", "critical")
    return None


def _http_get(url: str, timeout: int = 20) -> tuple[int, str, str]:
    res = runner.run(
        ["curl", "-sk", "--max-time", str(timeout), "-D", "-", url],
        timeout=timeout + 10,
    )
    raw = res.stdout or ""
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""

    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", head)
    status = int(m.group(1)) if m else int(res.exit_code)
    ctype = ""
    for line in head.splitlines():
        if line.lower().startswith("content-type:"):
            ctype = line.split(":", 1)[1].strip()
    return status, ctype, body[:20000]


def enrich_findings(finding_list: list, timeout: int = 20,
                    max_fetches: int = 25) -> list:
    """Fetch body evidence for discovered resources and classify by content.

    Every discovered 200 is sampled (bounded, redacted). High-value paths and
    dangerous body signatures (debug consoles, exposed secrets, directory
    listings, phpinfo) are promoted to the appropriate severity.
    """
    out: list = []
    fetches = 0

    for f in finding_list:
        if (f.tool or "").lower() != "gobuster":
            out.append(f)
            continue
        m = _STATUS_RE.search(f.evidence or "")
        if not m or int(m.group(1)) != 200 or fetches >= max_fetches:
            out.append(f)
            continue

        status, ctype, body = _http_get(f.endpoint, timeout)
        fetches += 1
        if status != 200 or not body.strip():
            out.append(f)
            continue

        candidates = [
            (title, sev) for rx, title, sev in _EXPOSED_PATTERNS
            if rx.search(f.endpoint or "")
        ]
        content_hit = _classify_body(body, ctype)
        if content_hit:
            candidates.append(content_hit)

        if not candidates:
            # Not high-value by itself — still attach a short redacted excerpt.
            f.evidence = (
                f"{f.evidence}\n\nGET {f.endpoint} -> HTTP {status} "
                f"{ctype}\n{_snippet(redact_secrets(body))}"
            )
            out.append(f)
            continue

        candidates.sort(key=lambda c: _RANK.get(c[1], 99))
        title, sev = candidates[0]

        f.severity = sev
        f.title = title
        f.confidence = "high"
        f.description = (
            f"Publicly readable resource at {f.endpoint} "
            f"(HTTP {status}, {ctype or 'unknown content-type'}). Content was "
            f"captured as evidence with secret values redacted."
        )
        f.evidence = (
            f"GET {f.endpoint}\nHTTP {status} {ctype}\n\n"
            f"{redact_secrets(body)}"
        )
        f.remediation = (
            "Remove the resource from the web root, disable debug mode in "
            "production, and rotate every exposed credential/key immediately."
        )
        f.references = [
            "https://owasp.org/www-community/vulnerabilities/Information_exposure"
        ]
        out.append(f)

    return out


class _Run:
    """Small helper collecting command + output records for one assessment.

    ``execute`` may be called from multiple threads (one per web port). The
    subprocess itself runs without the lock; only the shared ``Assessment``
    mutations are serialized.
    """

    def __init__(self, target: str, assessment: report_mod.Assessment,
                 on_event=None):
        self.target = target
        self.a = assessment
        self._lock = threading.Lock()
        self.on_event = on_event

    def _emit(self, **event):
        if self.on_event:
            try:
                self.on_event(**event)
            except Exception:  # noqa: BLE001
                pass

    def execute(self, tool: str, argv: list[str], *, timeout: int,
                artifact: str, base_url: str = "", key: str | None = None
                ) -> runner.RunResult:
        step_key = key or f"{tool}@{base_url or self.target}"
        label = f"{tool} [{base_url or self.target}]"
        agent = "Web Agent" if tool in {"nikto", "gobuster"} else "Recon Agent"
        self._emit(type="step_start", key=step_key, label=label, tool=tool,
                   agent=agent, timeout=timeout,
                   command=" ".join(shlex.quote(x) for x in argv))
        log.info("exec: %s", " ".join(argv))
        try:
            result = runner.run(argv, timeout=timeout, artifact_name=artifact)
        except Exception as exc:  # noqa: BLE001
            self._emit(type="step_end", key=step_key, label=label, agent=agent,
                       status="error", exit_code=None, duration_ms=None,
                       findings=0)
            raise

        captured = result.stdout or ""
        if result.stderr:
            captured += "\n--- stderr ---\n" + result.stderr

        parsed = findings_mod.parse_output(
            tool, result.stdout or "", self.target, base_url
        )

        with self._lock:
            self.a.commands.append({
                "tool": tool,
                "command": " ".join(shlex.quote(x) for x in argv),
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "artifact": result.artifact_path or "",
                "timeout": timeout,
            })
            if result.artifact_path:
                self.a.artifacts.append(result.artifact_path)
            self.a.raw[label] = captured
            self.a.findings.extend(parsed)

        self._emit(type="step_end", key=step_key, label=label, agent=agent,
                   status=("done" if result.exit_code == 0 else "error"),
                   exit_code=result.exit_code, duration_ms=result.duration_ms,
                   findings=len(parsed))

        try:
            memory.memory.add_document(
                text=result.stdout or "",
                metadata={"tool": tool, "target": self.target,
                          "base_url": base_url or self.target,
                          "exit_code": result.exit_code},
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("memory add failed: %s", exc)

        return result


def _nikto_argv(base: str, maxtime: int = NIKTO_MAXTIME) -> list[str]:
    """nikto with a hard per-host time cap so WAFs cannot stall the scan."""
    return ["nikto", "-h", base, "-Tuning", "1", "-nointeractive",
            "-maxtime", f"{maxtime}s"]


def _nmap_web_argv(host: str, ports: list[int], nmap_rate: int) -> list[str]:
    return ["nmap", "-Pn", "-sV", "--version-light", "-T4",
            "--max-rate", str(nmap_rate),
            "--max-retries", NMAP_MAX_RETRIES,
            "--host-timeout", NMAP_HOST_TIMEOUT,
            "-p", ",".join(str(p) for p in ports), host]


def _probe_catchall(base: str, user_agent: str,
                    timeout: int = 15) -> tuple[int | None, int | None]:
    """Probe a random path to learn the app's 'everything' response.

    Many apps are SPAs (HTTP 200 for every path) or blanket-redirect to HTTPS.
    Both trip gobuster's wildcard guard and abort the whole scan, so we detect
    the catch-all first and give gobuster the matching exclusion.
    """
    probe = f"{base}/kpm-{uuid.uuid4().hex}"
    res = runner.run(
        ["curl", "-sk", "-A", user_agent, "--max-time", str(timeout),
         "-o", "/dev/null", "-w", "%{http_code} %{size_download}", probe],
        timeout=timeout + 10,
    )
    parts = (res.stdout or "").strip().split()
    status = int(parts[0]) if parts and parts[0].isdigit() else None
    length = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    return status, length


def _gobuster_argv(base: str, wordlist: str, threads: int,
                   user_agent: str, delay_ms: int = 0) -> list[str]:
    argv = ["gobuster", "dir", "-u", base, "-w", wordlist, "-a", user_agent,
            "-t", str(threads), "-q", "--no-error", "-k"]
    if delay_ms > 0:
        argv += ["--delay", f"{delay_ms}ms"]
    status, length = _probe_catchall(base, user_agent)
    if status in (301, 302, 303, 307, 308):
        # Blanket redirect (e.g. http -> https): blacklist those plus 404 so
        # the scan still surfaces any path that actually responds.
        argv += ["--status-codes-blacklist", "404,301,302,303,307,308"]
    elif status == 200 and length:
        # SPA catch-all: every unknown path returns the same body length.
        argv += ["--exclude-length", str(length)]
    return argv


def _scope_filtered_wordlist(wordlist: str, base: str, active_scope,
                             target_tag: str, port: int,
                             stamp: str) -> tuple[str, Path | None, int]:
    """Filter discovered paths that the active scope excludes."""
    if not active_scope.ex_paths:
        return wordlist, None, 0

    kept: list[str] = []
    removed = 0
    with Path(wordlist).open("r", encoding="utf-8", errors="replace") as stream:
        for raw in stream:
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            clean = entry.lstrip("/")
            if ".." in Path(clean).parts or "://" in clean:
                removed += 1
                continue
            allowed, _reason = active_scope.check(f"{base.rstrip('/')}/{clean}")
            if allowed:
                kept.append(entry)
            else:
                removed += 1

    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix=f"{target_tag}_{port}_scope_",
        suffix=".txt", dir=runner.ARTIFACT_DIR, delete=False,
    )
    try:
        tmp.write("\n".join(kept) + ("\n" if kept else ""))
    finally:
        tmp.close()
    return tmp.name, Path(tmp.name), removed


def _scope_filtered_wordlist(wordlist: str, base: str, active_scope,
                             target_tag: str, port: int,
                             stamp: str) -> tuple[str, Path | None, int]:
    """Create a temporary wordlist with every out-of-scope path removed."""
    if not active_scope.ex_paths:
        return wordlist, None, 0

    kept: list[str] = []
    removed = 0
    with Path(wordlist).open("r", encoding="utf-8", errors="replace") as stream:
        for raw in stream:
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            clean = entry.lstrip("/")
            if ".." in Path(clean).parts or "://" in clean:
                removed += 1
                continue
            candidate = f"{base.rstrip('/')}/{clean}"
            allowed, _reason = active_scope.check(candidate)
            if allowed:
                kept.append(entry)
            else:
                removed += 1

    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix=f"{target_tag}_{port}_scope_",
        suffix=".txt", dir=runner.ARTIFACT_DIR, delete=False,
    )
    try:
        tmp.write("\n".join(kept) + ("\n" if kept else ""))
    finally:
        tmp.close()
    return tmp.name, Path(tmp.name), removed


def run_assessment(
    target: str,
    profile: str = "web",
    *,
    operator: str = "",
    wordlist: str | None = None,
    deep: bool = False,
    dry_run: bool = False,
    all_web_ports: bool = False,
    write_report: bool = True,
    nmap_timeout: int = 300,
    nikto_timeout: int = NIKTO_TIMEOUT,
    nikto_maxtime: int | None = None,
    web_timeout: int = 300,
    reports_dir: Path | None = None,
    on_event=None,
    job_id: str | None = None,
    job_source: str = "assess",
) -> report_mod.Assessment:
    """Run a scope-checked assessment. Never touches an unauthorized target."""
    profile = (profile or "web").lower()
    started = _iso()
    sc = scope.get_scope()
    allowed, reason = sc.check(target)
    jid = jobs.create_job(profile, target, operator, source=job_source,
                          job_id=job_id, agent="Assessment Agent")

    def emit(**event):
        try:
            jobs.record_event(jid, event)
        except Exception:  # noqa: BLE001 - tracking failure must not stop scan
            pass
        if on_event:
            try:
                on_event(event)
            except Exception:  # noqa: BLE001
                pass

    emit(type="scan_start", target=target, profile=profile, started=started)

    assessment = report_mod.Assessment(
        target=target,
        profile=profile,
        authorized=allowed,
        scope_reason=reason,
        operator=operator,
        program=dict(sc.program),
        rules=dict(sc.rules),
        started=started,
    )
    assessment.job_id = jid

    if not allowed:
        assessment.finished = _iso()
        log.warning("assessment denied for %s: %s", target, reason)
        if not dry_run and write_report:
            assessment.report_md, assessment.report_json = \
                report_mod.write_report(assessment, reports_dir)
        emit(type="scan_done", status="denied", findings=assessment.summary(),
             report_md=assessment.report_md, report_json=assessment.report_json,
             error=reason)
        return assessment

    host = scope.normalize_host(target)
    rules = sc.rules or {}
    rps = int(rules.get("max_requests_per_second", 5) or 5)
    threads = max(1, min(int(rules.get("max_concurrency", 10) or 10), 30))
    # Treat the program's request-rate ceiling conservatively for Nmap probe
    # packets too; don't silently inflate a low scope limit to 20pps.
    nmap_rate = max(1, rps)
    allowed_ports = [int(p) for p in (rules.get("allowed_ports") or [])]
    user_agent = (rules.get("user_agent")
                  or "KaliPentestMCP/1.0 (authorized bug-bounty assessment)")

    if not wordlist:
        if deep and SECLISTS_COMMON.exists():
            wordlist = str(SECLISTS_COMMON)
        elif BUNDLED_WORDLIST.exists():
            wordlist = str(BUNDLED_WORDLIST)
        elif SECLISTS_COMMON.exists():
            wordlist = str(SECLISTS_COMMON)

    run = _Run(target, assessment, on_event=emit)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = _safe(host)

    maxtime = int(nikto_maxtime) if nikto_maxtime else NIKTO_MAXTIME
    # nikto honours -maxtime but can still linger; cap the subprocess just
    # above it so we don't wait an extra 30s per port.
    eff_nikto_timeout = maxtime + 15 if nikto_maxtime else nikto_timeout
    skipped_steps: list[str] = []

    do_network = profile in ("network", "full")
    do_web = profile in ("web", "full")

    initial_plan = []
    if do_network:
        initial_plan.append({"key": "nmap-network", "label": "nmap network",
                             "agent": "Recon Agent", "timeout": nmap_timeout})
    if do_web:
        initial_plan.append({"key": "nmap-web", "label": "nmap web ports",
                             "agent": "Recon Agent", "timeout": nmap_timeout})
    emit(type="plan", steps=initial_plan)

    # Candidate web ports: explicit scope restriction wins, else the curated
    # fast set for the web profile / top-500 sweep for full.
    web_scan_ports = allowed_ports or WEB_PROFILE_PORTS

    # --- Dry run: report the intended plan without executing -----------
    if dry_run:
        planned = []
        if do_network:
            argv = ["nmap", "-Pn", "-sV", "-T4", "--top-ports", "500",
                    "--max-rate", str(nmap_rate)]
            if allowed_ports:
                argv += ["-p", ",".join(str(p) for p in allowed_ports)]
            argv.append(host)
            planned.append(argv)
        if do_web:
            planned.append(["nmap", "-Pn", "-sV", "--version-light", "-T4",
                            "--max-rate", str(nmap_rate),
                            "--max-retries", NMAP_MAX_RETRIES,
                            "--host-timeout", NMAP_HOST_TIMEOUT,
                            "-p", ",".join(str(p) for p in web_scan_ports),
                            host])
            planned.append(_nikto_argv(f"https://{host}", maxtime))
            planned.append(["gobuster", "dir", "-u", f"https://{host}",
                            "-w", wordlist or "<wordlist>",
                            "-t", str(threads), "-q", "--no-error", "-k"])
        for argv in planned:
            assessment.commands.append({
                "tool": argv[0],
                "command": " ".join(shlex.quote(x) for x in argv),
                "exit_code": None, "duration_ms": None,
                "artifact": "", "timeout": None,
            })
        assessment.finished = _iso()
        assessment.notes = "DRY RUN — no commands were executed."
        emit(type="scan_done", status="done", findings=assessment.summary(),
             report_md=None, report_json=None)
        return assessment

    # ------------------------------------------------------------------
    # Network profile / recon
    # ------------------------------------------------------------------
    if do_network:
        argv = ["nmap", "-Pn", "-sV", "-T4", "--top-ports", "500",
                "--max-rate", str(nmap_rate),
                "--max-retries", NMAP_MAX_RETRIES,
                "--host-timeout", NMAP_HOST_TIMEOUT]
        if allowed_ports:
            argv += ["-p", ",".join(str(p) for p in allowed_ports)]
        argv.append(host)
        run.execute("nmap", argv, timeout=nmap_timeout,
                    artifact=f"{tag}_nmap_network_{stamp}.txt",
                    key="nmap-network")

    # ------------------------------------------------------------------
    # Web profile
    # ------------------------------------------------------------------
    web_ports: list[int] = []
    if do_web:
        argv = _nmap_web_argv(host, web_scan_ports, nmap_rate)
        res = run.execute("nmap", argv, timeout=nmap_timeout,
                          artifact=f"{tag}_nmap_web_{stamp}.txt",
                          key="nmap-web")

        discovered = [p for p, s in _open_tcp(res.stdout)
                      if p in WEB_PORTS or "http" in s]
        if allowed_ports:
            discovered = [p for p in discovered if p in allowed_ports]

        if all_web_ports:
            web_ports = discovered
        else:
            # Fast path: if the canonical web ports are open, they are what
            # the application actually serves — skip CDN/alt duplicates.
            web_ports = [p for p in discovered if p in CANONICAL_WEB_PORTS]

        if not web_ports:
            # Fall back to whatever was discovered, else best effort.
            web_ports = discovered or [
                p for p in (allowed_ports or []) if p in WEB_PORTS
            ] or [443, 80]

        web_plan = list(initial_plan)
        for port in web_ports:
            base = _base_url(host, port)
            web_plan.append({"key": f"nikto@{port}",
                             "label": f"nikto [{base}]", "agent": "Web Agent",
                             "timeout": eff_nikto_timeout})
            if wordlist and Path(wordlist).exists():
                web_plan.append({"key": f"gobuster@{port}",
                                 "label": f"gobuster [{base}]", "agent": "Web Agent",
                                 "timeout": web_timeout})
        emit(type="plan", steps=web_plan)

        if len(web_ports) > 1:
            log.info("web ports to scan: %s (parallel=%d)",
                     web_ports, min(len(web_ports), WEB_WORKERS))

        def _scan_port(port: int) -> None:
            base = _base_url(host, port)
            try:
                if sc.ex_paths:
                    reason = "Nikto cannot reliably enforce configured path exclusions"
                    skipped_steps.append(f"nikto [{base}] ({reason})")
                    emit(type="step_skipped", key=f"nikto@{port}",
                         label=f"nikto [{base}]", agent="Web Agent", reason=reason)
                else:
                    run.execute("nikto", _nikto_argv(base, maxtime),
                                timeout=eff_nikto_timeout,
                                artifact=f"{tag}_nikto_{port}_{stamp}.txt",
                                base_url=base, key=f"nikto@{port}")
                if wordlist and Path(wordlist).exists():
                    scoped_wordlist, temporary_wordlist, removed = \
                        _scope_filtered_wordlist(wordlist, base, sc, tag,
                                                 port, stamp)
                    if removed:
                        skipped_steps.append(
                            f"gobuster [{base}] omitted {removed} out-of-scope wordlist paths"
                        )
                    try:
                        if Path(scoped_wordlist).stat().st_size == 0:
                            reason = "no in-scope paths remain in the wordlist"
                            skipped_steps.append(f"gobuster [{base}] ({reason})")
                            emit(type="step_skipped", key=f"gobuster@{port}",
                                 label=f"gobuster [{base}]", agent="Web Agent",
                                 reason=reason)
                        else:
                            # With path-specific exclusions, run sequentially
                            # and pace requests at the configured scope rate.
                            gobuster_threads = 1 if sc.ex_paths else min(threads, max(1, rps))
                            delay_ms = (math.ceil(1000 / max(1, rps))
                                        if sc.ex_paths else
                                        math.ceil(1000 * gobuster_threads / max(1, rps)))
                            run.execute(
                                "gobuster",
                                _gobuster_argv(base, scoped_wordlist,
                                               gobuster_threads, user_agent,
                                               delay_ms=delay_ms),
                                timeout=web_timeout,
                                artifact=f"{tag}_gobuster_{port}_{stamp}.txt",
                                base_url=base, key=f"gobuster@{port}",
                            )
                    finally:
                        if temporary_wordlist:
                            Path(temporary_wordlist).unlink(missing_ok=True)
            except Exception as exc:  # noqa: BLE001 - one port must not kill the run
                log.warning("port %s scan failed: %s", port, exc)

        if web_ports:
            workers = (1 if sc.ex_paths else
                       max(1, min(len(web_ports), WEB_WORKERS)))
            if workers == 1:
                for port in web_ports:
                    _scan_port(port)
            else:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    list(pool.map(_scan_port, web_ports))

    # ------------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------------
    in_scope_findings = []
    for finding in assessment.findings:
        if not finding.endpoint:
            in_scope_findings.append(finding)
            continue
        endpoint_allowed, endpoint_reason = sc.check(finding.endpoint)
        if endpoint_allowed:
            in_scope_findings.append(finding)
        else:
            skipped_steps.append(
                f"filtered out-of-scope finding endpoint {finding.endpoint}: {endpoint_reason}"
            )
    assessment.findings = in_scope_findings
    assessment.findings = findings_mod.dedupe(assessment.findings)
    if do_web and rules.get("fetch_exposed_files", True):
        assessment.findings = enrich_findings(
            assessment.findings,
            max_fetches=int(rules.get("max_evidence_fetches", 25) or 25),
        )
        assessment.findings = findings_mod.dedupe(assessment.findings)
    assessment.finished = _iso()
    if skipped_steps:
        assessment.notes = (assessment.notes or "") + "\n\n## Scope-safe omissions\n" + \
            "\n".join(f"- {line}" for line in dict.fromkeys(skipped_steps))
    if write_report:
        assessment.report_md, assessment.report_json = \
            report_mod.write_report(assessment, reports_dir)
    log.info("assessment complete: %d findings", len(assessment.findings))
    emit(type="scan_done", status="done", findings=assessment.summary(),
         report_md=assessment.report_md, report_json=assessment.report_json)
    return assessment


def reparse_from_report(json_path: str | Path,
                        reports_dir: Path | None = None) -> report_mod.Assessment:
    """Rebuild findings from a prior assessment's artifacts only.

    This function deliberately does not probe the target. It is safe for
    tuning parser/deduplication rules against already collected evidence.
    """
    assessment = report_mod.load_assessment(json_path)
    parsed: list = []
    raw: dict[str, str] = {}
    for command in assessment.commands:
        tool = str(command.get("tool") or "").lower()
        artifact = command.get("artifact") or ""
        if not artifact or not Path(artifact).is_file():
            continue
        content = Path(artifact).read_text(encoding="utf-8", errors="replace")
        raw[tool] = content
        argv = shlex.split(command.get("command") or "")
        base_url = ""
        for flag in ("-h", "-u"):
            if flag in argv:
                index = argv.index(flag)
                if index + 1 < len(argv):
                    base_url = argv[index + 1]
                break
        parsed.extend(findings_mod.parse_output(
            tool, content, assessment.target, base_url
        ))

    assessment.findings = findings_mod.dedupe(parsed)
    assessment.raw = raw
    assessment.finished = _iso()
    assessment.report_md, assessment.report_json = report_mod.write_report(
        assessment, reports_dir or Path(json_path).parent
    )
    return assessment
