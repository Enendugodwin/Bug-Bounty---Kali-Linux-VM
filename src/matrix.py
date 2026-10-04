"""Full tool-matrix scan.

Runs every applicable installed tool against a scope-checked target and
aggregates findings into one report. Intrusive tools (sqlmap, and anything
gated by ``allow_intrusive``) are skipped unless the scope enables them.
Tools that are not installed or not usable (e.g. an inactive GVM daemon) are
recorded as skipped rather than silently ignored.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import findings as findings_mod
from . import jobs, memory, report as report_mod, runner, scope, waf
from .cve import parse_nmap_vuln, parse_nuclei, redact
from .findings import Finding, dedupe, parse_output

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = PROJECT_ROOT / "artifacts"
WORDLIST = PROJECT_ROOT / "wordlists" / "web-small.txt"
SECLISTS_COMMON = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)

# Which specialized agent is "in charge" of each tool.
AGENT_BY_TOOL = {
    "whatweb": "Recon Agent", "nmap": "Recon Agent", "nmap-vuln": "Recon Agent",
    "dnsrecon": "Recon Agent", "dig": "Recon Agent",
    "gobuster": "Web Agent", "ffuf": "Web Agent", "dirb": "Web Agent",
    "nikto": "Web Agent", "wapiti": "Web Agent", "wpscan": "Web Agent",
    "nuclei": "CVE Agent", "searchsploit": "CVE Agent",
    "sqlmap": "Exploit Agent",
}
LEAD_AGENT = "Matrix Agent"


def agent_for(tool: str) -> str:
    return AGENT_BY_TOOL.get(tool, LEAD_AGENT)

_LEVEL_MAP = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(t: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", t).strip("_") or "target"


def _domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_whatweb(text: str, target: str, base_url: str = "") -> list:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if "[" not in line or "]" not in line:
            continue
        if not line.startswith("http") and "://" not in line:
            continue
        plugins = re.findall(r"([A-Za-z0-9_\-]+)\[([^\]]*)\]", line)
        summary = ", ".join(f"{k}={v}" for k, v in plugins if v) or line
        out.append(Finding(
            id=findings_mod._fid("whatweb fingerprint", line[:80], target),
            title="Technology fingerprint (whatweb)",
            severity="info", target=target, tool="whatweb",
            endpoint=line.split(" ", 1)[0],
            confidence="high",
            description="Identified technologies / versions.",
            evidence=summary[:1500],
            remediation="Reduce exposed version information where feasible.",
            references=["https://github.com/urbanadventurer/WhatWeb"],
        ))
    return out


def parse_dirb(text: str, target: str, base_url: str = "") -> list:
    out = []
    rx = re.compile(r"^\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)", re.I)
    for line in (text or "").splitlines():
        m = rx.search(line.strip())
        if not m:
            continue
        url, code, size = m.group(1), int(m.group(2)), m.group(3)
        sev = "info"
        low = url.lower()
        if code == 200:
            for needle, s in ((".env", "high"), (".git", "high"), (".bak", "medium"),
                              ("backup", "medium"), ("admin", "medium"),
                              ("config", "medium"), ("console", "medium")):
                if needle in low:
                    sev = s
                    break
            if sev == "info":
                sev = "low"
        out.append(Finding(
            id=findings_mod._fid("dirb path " + url, url, target),
            title=f"Discovered path (dirb): {url}",
            severity=sev, target=target, tool="dirb", endpoint=url,
            confidence="high" if code == 200 else "low",
            description=f"dirb found a resource (HTTP {code}).",
            evidence=f"{url} (CODE:{code}|SIZE:{size})",
            remediation="Confirm the resource should be publicly reachable.",
            references=["https://owasp.org/www-community/attacks/Forced_browsing"],
        ))
    return out


def parse_wapiti(path: str | Path, target: str) -> list:
    out = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return out
    vulns = data.get("vulnerabilities") or {}
    for name, items in vulns.items():
        for item in items or []:
            level = str(item.get("level", "2"))
            sev = _LEVEL_MAP.get(level, "medium")
            endpoint = item.get("path") or item.get("url") or target
            info = str(item.get("info") or name)[:1000]
            evidence = str(item.get("http_request") or item.get("parameter") or name)[:1500]
            # Wapiti's remote OpenSSL CCS signature is especially prone to
            # false positives behind TLS-terminating CDNs/proxies.
            tls_ccs_heuristic = "cve-2014-0224" in f"{name} {info} {evidence}".lower()
            if tls_ccs_heuristic:
                sev = "medium"
                info += (" Detection is heuristic; validate the TLS terminator and "
                         "OpenSSL version manually (CDN/proxy termination can "
                         "produce false positives).")
            out.append(Finding(
                id=findings_mod._fid("wapiti " + name, endpoint, target),
                title=f"wapiti: {name}",
                severity=sev, target=target, tool="wapiti", endpoint=endpoint,
                confidence="low" if tls_ccs_heuristic else "medium",
                description=info,
                evidence=evidence,
                remediation="Review and remediate the reported weakness.",
                references=["https://wapiti-scanner.github.io/"],
                validation_status=("needs_manual_validation" if tls_ccs_heuristic
                                   else "scanner_match"),
            ))
    # wapiti also reports "anomalies"
    for name, items in (data.get("anomalies") or {}).items():
        for item in items or []:
            endpoint = item.get("path") or target
            out.append(Finding(
                id=findings_mod._fid("wapiti-anom " + name, endpoint, target),
                title=f"wapiti anomaly: {name}",
                severity="low", target=target, tool="wapiti", endpoint=endpoint,
                confidence="low",
                description=str(item.get("info") or name)[:800],
                evidence=str(item.get("http_request") or name)[:1200],
                remediation="Review the anomaly.",
                references=["https://wapiti-scanner.github.io/"],
            ))
    return out


def parse_wpscan(path: str | Path, target: str) -> list:
    out = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return out

    ver = (data.get("version") or {})
    if ver.get("number") and ver.get("vulnerabilities"):
        for v in ver["vulnerabilities"]:
            out.append(Finding(
                id=findings_mod._fid("wpscan core " + str(v.get("title")), target, target),
                title=f"WordPress core: {v.get('title')}",
                severity="high", target=target, tool="wpscan", endpoint=target,
                confidence="medium",
                description=f"WordPress {ver.get('number')} vulnerability.",
                evidence=json.dumps(v)[:1000],
                remediation="Update WordPress core to a patched version.",
                references=[v.get("references", {}).get("url", []) or [x for x in ([v.get("references")] ) if x]][:3] if v.get("references") else [],
            ))
    for plugin, pdata in (data.get("plugins") or {}).items():
        for v in (pdata.get("vulnerabilities") or []):
            out.append(Finding(
                id=findings_mod._fid("wpscan plugin " + plugin + str(v.get("title")), target, target),
                title=f"WordPress plugin ({plugin}): {v.get('title')}",
                severity="high", target=target, tool="wpscan", endpoint=target,
                confidence="medium",
                description=f"Plugin {plugin} vulnerability.",
                evidence=json.dumps(v)[:1000],
                remediation="Update or remove the vulnerable plugin.",
                references=[],
            ))
    for fi in (data.get("interesting_findings") or []):
        out.append(Finding(
            id=findings_mod._fid("wpscan finding " + str(fi.get("to_s")), target, target),
            title=f"wpscan: {fi.get('to_s') or fi.get('type')}",
            severity="low", target=target, tool="wpscan", endpoint=target,
            confidence="medium",
            description=str(fi.get("to_s") or fi.get("type")),
            evidence=json.dumps(fi)[:1000],
            remediation="Review the WordPress exposure.",
            references=[],
        ))
    return out


def parse_sqlmap(text: str, target: str, base_url: str = "") -> list:
    out = []
    low = (text or "").lower()
    if "is vulnerable" in low or "sqlmap identified the following injection point" in low:
        params = re.findall(r"Parameter:\s*([^\s]+)", text or "")
        out.append(Finding(
            id=findings_mod._fid("sqlmap injection", target, target),
            title="SQL injection (sqlmap)",
            severity="critical", target=target, tool="sqlmap", endpoint=target,
            confidence="high",
            description="sqlmap confirmed an injectable parameter.",
            evidence=("Parameters: " + ", ".join(params) if params else "sqlmap reported injection")[:1500],
            remediation="Use parameterised queries and patch the injection.",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        ))
    return out


def parse_searchsploit(path: str | Path, target: str) -> list:
    out = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return out
    for item in (data.get("RESULTS_EXPLOIT") or []):
        title = item.get("Title") or ""
        edb = item.get("EDB-ID") or ""
        out.append(Finding(
            id=findings_mod._fid("searchsploit " + title, str(edb), target),
            title=f"Possible Exploit-DB reference: {title[:100]}",
            severity="info", target=target, tool="searchsploit", endpoint=target,
            confidence="low",
            description=(f"Exploit-DB entry EDB-{edb} matched a technology keyword; "
                         "applicability and affected version are not confirmed."),
            evidence=f"EDB-{edb}: {title}",
            remediation="Confirm applicability and patch the affected component.",
            references=[f"https://www.exploit-db.com/exploits/{edb}"] if edb else [],
            validation_status="needs_manual_validation",
        ))
    return out


def parse_searchsploit_stdout(text: str, target: str, base_url: str = "") -> list:
    """Parse `searchsploit --json` output printed to stdout."""
    out = []
    data = None
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        m = re.search(r"\{.*\}", text or "", re.S)
        if m:
            try:
                data = json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                data = None
    if not isinstance(data, dict):
        return out
    for item in (data.get("RESULTS_EXPLOIT") or []):
        title = item.get("Title") or ""
        edb = item.get("EDB-ID") or ""
        out.append(Finding(
            id=findings_mod._fid("searchsploit " + title, str(edb), target),
            title=f"Possible Exploit-DB reference: {title[:100]}",
            severity="info", target=target, tool="searchsploit",
            endpoint=target, confidence="low",
            description=(f"Exploit-DB entry EDB-{edb} matched a technology keyword; "
                         "applicability and affected version are not confirmed."),
            evidence=f"EDB-{edb}: {title}",
            remediation="Confirm applicability and patch the affected component.",
            references=[f"https://www.exploit-db.com/exploits/{edb}"] if edb else [],
            validation_status="needs_manual_validation",
        ))
    return out


def parse_dnsrecon(path: str | Path, target: str) -> list:
    out = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return out
    records = data if isinstance(data, list) else data.get("records", [])
    for rec in records or []:
        name = rec.get("name") or rec.get("target") or ""
        rtype = rec.get("type") or ""
        address = rec.get("address") or rec.get("target") or ""
        out.append(Finding(
            id=findings_mod._fid(f"dns {rtype} {name}", str(address), target),
            title=f"DNS record: {rtype} {name}",
            severity="info", target=target, tool="dnsrecon", endpoint=name,
            confidence="high",
            description=f"Discovered {rtype} record.",
            evidence=f"{rtype} {name} -> {address}",
            remediation="Review for unintended exposure.",
            references=[],
        ))
    return out


_PARSERS_BY_TEXT = {
    "nmap": lambda t, target, base: parse_output("nmap", t, target, base),
    "nikto": lambda t, target, base: parse_output("nikto", t, target, base),
    "gobuster": lambda t, target, base: parse_output("gobuster", t, target, base),
    "ffuf": lambda t, target, base: parse_output("ffuf", t, target, base),
    "nuclei": lambda t, target, base: parse_nuclei(t, target),
}


def _open_web_ports(nmap_text: str) -> list[int]:
    ports = [int(p) for p, s in _PORT_RE.findall(nmap_text or "")
             if int(p) in WEB_PORTS or "http" in s.lower()]
    return ports or [443, 80]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_matrix(
    target: str,
    *,
    operator: str = "",
    wordlist: str | None = None,
    rate: int = 20,
    cmd_timeout: int = 900,
    include_intrusive: bool = False,
    confirm_intrusive: bool = False,
    reports_dir: Path | None = None,
    on_event=None,
    job_id: str | None = None,
    job_source: str = "matrix",
) -> report_mod.Assessment:
    started = _iso()
    jid = jobs.create_job("matrix", target, operator, source=job_source,
                          job_id=job_id, agent="Matrix Agent")

    def emit(**ev):
        try:
            jobs.record_event(jid, ev)
        except Exception:  # noqa: BLE001 - progress persistence must not break a scan
            pass
        if on_event:
            try:
                on_event(ev)
            except Exception:  # noqa: BLE001
                pass

    emit(type="scan_start", target=target, profile="matrix", started=started)

    sc = scope.get_scope()
    allowed, reason = sc.check(target)
    a = report_mod.Assessment(
        target=target, profile="matrix", authorized=allowed,
        scope_reason=reason, operator=operator,
        program=dict(sc.program), rules=dict(sc.rules), started=started,
    )
    a.job_id = jid
    if not allowed:
        a.finished = _iso()
        a.report_md, a.report_json = report_mod.write_report(a, reports_dir)
        emit(type="scan_done", status="denied", findings=a.summary(),
             report_md=a.report_md, report_json=a.report_json,
             error=reason)
        return a

    if include_intrusive and not confirm_intrusive:
        emit(type="scan_error", error="Intrusive tools require explicit confirmation.")
        raise PermissionError("SQLMap requires --intrusive and --confirm-intrusive.")
    if include_intrusive and not sc.rules.get("allow_intrusive", False):
        emit(type="scan_error", error="scope rules disallow intrusive testing")
        raise PermissionError(
            "scope.yaml rules.allow_intrusive must be true for SQLMap."
        )

    # --- WAF / edge block preflight ----------------------------------
    # Stop before the tool matrix if the edge refuses our probes; otherwise
    # every scanner reports block-page artifacts as findings.
    user_agent = str(sc.rules.get("user_agent") or "KaliPentestMCP/1.0")
    block = waf.detect_block(target, user_agent=user_agent)
    if block.kind or block.vendor:
        a.block = block.to_dict()
    if block.blocked:
        a.scan_status = "inconclusive"
        a.finished = _iso()
        lines = [
            "## Scan inconclusive — edge/WAF block",
            f"- {block.describe()}",
            "- No scanner results are reported because the target refused "
            "the automated requests.",
        ]
        lines += [f"- {ev}" for ev in block.evidence]
        a.notes = (a.notes or "") + "\n".join(lines)
        a.report_md, a.report_json = report_mod.write_report(a, reports_dir)
        emit(type="waf_block", target=target, vendor=block.vendor,
             status=block.status, evidence=block.evidence)
        emit(type="scan_done", status="blocked", findings=a.summary(),
             report_md=a.report_md, report_json=a.report_json,
             reason=block.describe())
        return a

    host = scope.normalize_host(target)
    url = f"https://{host}"
    http_url = f"http://{host}"
    domain = _domain(host)
    wl = wordlist or str(WORDLIST)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = _safe(host)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    skipped: list[str] = []

    def out_file(name: str) -> Path:
        return ARTIFACTS / f"{tag}_{name}_{stamp}.json"

    def run_tool(tool: str, argv: list[str], parser, *, base_url: str = "",
                 timeout: int = cmd_timeout, artifact: str | None = None,
                 parse_file: Path | None = None, text_parser=None,
                 file_parser=None, key: str | None = None,
                 label: str | None = None):
        k = key or tool
        lbl = label or tool
        if shutil.which(argv[0]) is None:
            skipped.append(f"{tool} (not installed)")
            emit(type="step_skipped", key=k, label=lbl, agent=agent_for(tool),
                 reason="not installed")
            return None
        emit(type="step_start", key=k, label=lbl, tool=tool,
             agent=agent_for(tool), timeout=timeout,
             command=" ".join(shlex.quote(x) for x in argv))
        before = len(a.findings)
        try:
            res = runner.run(argv, timeout=timeout,
                             artifact_name=artifact or f"{tag}_{tool}_{stamp}.txt")
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"{tool} (error: {exc})")
            emit(type="step_end", key=k, label=lbl, agent=agent_for(tool),
                 status="error", exit_code=None, duration_ms=None,
                 findings=len(a.findings) - before)
            return None
        a.commands.append({
            "tool": tool,
            "command": " ".join(shlex.quote(x) for x in argv),
            "exit_code": res.exit_code,
            "duration_ms": res.duration_ms,
            "artifact": res.artifact_path or "",
            "timeout": timeout,
        })
        if res.artifact_path:
            a.artifacts.append(res.artifact_path)
        captured = res.stdout or ""
        if res.stderr:
            captured += "\n--- stderr ---\n" + res.stderr
        a.raw[tool] = redact(captured)
        if file_parser is not None and parse_file is not None and Path(parse_file).exists():
            a.findings.extend(file_parser(parse_file, target))
        if text_parser is not None:
            a.findings.extend(text_parser(res.stdout or "", target, base_url))
        try:
            memory.memory.add_document(
                text=res.stdout or "",
                metadata={"tool": tool, "target": target,
                          "exit_code": res.exit_code},
            )
        except Exception:  # noqa: BLE001
            pass
        emit(type="step_end", key=k, label=lbl, agent=agent_for(tool),
             status=("done" if res.exit_code == 0 else "error"),
             exit_code=res.exit_code, duration_ms=res.duration_ms,
             findings=len(a.findings) - before)
        return res

    # --- Recon --------------------------------------------------------
    whatweb = run_tool("whatweb", ["whatweb", "-q", "--no-errors", url],
                       None, base_url=url, timeout=120,
                       text_parser=parse_whatweb)

    nmap = run_tool("nmap", ["nmap", "-Pn", "-sV", "--version-light", "-T4",
                             "--max-rate", str(max(20, rate * 5)), "-F", host],
                    None, timeout=300, text_parser=_PARSERS_BY_TEXT["nmap"])
    ports = _open_web_ports(nmap.stdout if nmap else "")

    run_tool("nmap-vuln", ["nmap", "-Pn", "-sV", "--script", "vuln",
                           "--version-light", "-T4", "--max-rate",
                           str(max(20, rate * 5)), host],
             None, timeout=min(cmd_timeout, 600),
             text_parser=lambda t, target, base: parse_nmap_vuln(t, target))

    run_tool("dnsrecon", ["dnsrecon", "-d", domain, "-j", str(out_file("dnsrecon"))],
             None, timeout=180, parse_file=out_file("dnsrecon"),
             file_parser=parse_dnsrecon)
    run_tool("dig", ["dig", "+short", host], None, timeout=60,
             text_parser=lambda t, target, base: [])

    # --- Web discovery (dedupe bases, cap to 2 to stay polite) --------
    bases: list[str] = []
    for port in ports:
        if port in (443, 8443):
            b = f"https://{host}" if port == 443 else f"https://{host}:{port}"
        else:
            b = f"http://{host}" if port == 80 else f"http://{host}:{port}"
        if b not in bases:
            bases.append(b)

    plan: list[dict] = []
    for lbl in ("whatweb", "nmap", "nmap-vuln", "dnsrecon", "dig"):
        plan.append({"key": lbl, "label": lbl, "agent": agent_for(lbl)})
    for base in bases[:2]:
        bslug = _safe(base)
        for tool, tmo in (("nikto", 200), ("gobuster", 300),
                          ("ffuf", 300), ("dirb", 300)):
            plan.append({"key": f"{tool}@{bslug}",
                         "label": f"{tool} ({base})", "timeout": tmo,
                         "agent": agent_for(tool)})
    plan.append({"key": "wapiti", "label": "wapiti", "timeout": 600,
                 "agent": agent_for("wapiti")})
    plan.append({"key": "wpscan", "label": "wpscan", "timeout": 400,
                 "agent": agent_for("wpscan")})
    plan.append({"key": "nuclei", "label": "nuclei", "timeout": cmd_timeout,
                 "agent": agent_for("nuclei")})
    plan.append({"key": "sqlmap", "label": "sqlmap", "timeout": 400,
                 "agent": agent_for("sqlmap")})
    plan.append({"key": "searchsploit", "label": "searchsploit", "timeout": 90,
                 "agent": agent_for("searchsploit")})
    emit(type="plan", steps=plan)

    for base in bases[:2]:
        bslug = _safe(base)

        run_tool("nikto", ["nikto", "-h", base, "-Tuning", "1",
                           "-maxtime", "120s", "-nointeractive"],
                 None, base_url=base, timeout=200, key=f"nikto@{bslug}",
                 label=f"nikto ({base})",
                 text_parser=_PARSERS_BY_TEXT["nikto"])
        run_tool("gobuster", ["gobuster", "dir", "-u", base, "-w", wl,
                              "-t", "20", "-q", "--no-error", "-k"],
                 None, base_url=base, timeout=300, key=f"gobuster@{bslug}",
                 label=f"gobuster ({base})",
                 text_parser=_PARSERS_BY_TEXT["gobuster"])
        run_tool("ffuf", ["ffuf", "-u", f"{base}/FUZZ", "-w", wl, "-of", "json",
                          "-o", str(out_file(f"ffuf_{bslug}")), "-mc",
                          "200,204,301,302,307,401,403", "-t", "20",
                          "-rate", str(rate), "-s"],
                 None, base_url=base, timeout=300, key=f"ffuf@{bslug}",
                 label=f"ffuf ({base})",
                 parse_file=out_file(f"ffuf_{bslug}"),
                 file_parser=lambda p, target, base=base: parse_output(
                     "ffuf", Path(p).read_text(encoding="utf-8", errors="replace"),
                     target, base))
        run_tool("dirb", ["dirb", base, wl, "-S", "-r"],
                 None, base_url=base, timeout=300, key=f"dirb@{bslug}",
                 label=f"dirb ({base})",
                 text_parser=lambda t, target, base=base: parse_dirb(t, target, base))

    # --- Web application scanners ------------------------------------
    run_tool("wapiti", ["wapiti", "-u", url, "--flush-session", "-f", "json",
                        "-o", str(out_file("wapiti"))],
             None, timeout=600, parse_file=out_file("wapiti"),
             file_parser=parse_wapiti)
    run_tool("wpscan", ["wpscan", "--url", url, "--no-banner",
                        "--disable-tls-checks", "--random-user-agent",
                        "--format", "json", "-o", str(out_file("wpscan")),
                        "--enumerate", "vp,vt", "--plugins-detection", "passive",
                        "--request-timeout", "15", "--connect-timeout", "10"],
             None, timeout=400, parse_file=out_file("wpscan"),
             file_parser=parse_wpscan)

    # --- CVE / nuclei -------------------------------------------------
    from .cve import _nuclei_args
    run_tool("nuclei", _nuclei_args([url, http_url], severity="high,critical",
                                    rate=rate),
             None, timeout=cmd_timeout,
             text_parser=lambda t, target, base: parse_nuclei(t, target))

    # --- Intrusive (gated) -------------------------------------------
    if include_intrusive:
        run_tool("sqlmap", ["sqlmap", "-u", url, "--batch", "--crawl=1",
                            "--level=1", "--risk=1", "--smart", "--random-agent",
                            "--timeout=10", "--retries=1"],
                 None, timeout=400, text_parser=parse_sqlmap)
    else:
        skipped.append("sqlmap (requires explicit intrusive confirmation)")
        emit(type="step_skipped", key="sqlmap", label="sqlmap",
             agent=agent_for("sqlmap"), reason="explicit intrusive confirmation not supplied")

    # --- Exploit-DB correlation from fingerprints --------------------
    terms = []
    if whatweb is not None:
        terms = list(dict.fromkeys(re.findall(
            r"([A-Za-z][A-Za-z0-9_-]{2,})\[", whatweb.stdout or "")))[:6]
    terms = terms or ["nginx", "flask", "werkzeug"]
    run_tool("searchsploit", ["searchsploit", "--json", *terms],
             None, timeout=90, text_parser=parse_searchsploit_stdout)

    # --- Not applicable -------------------------------------------------
    for na in ("enum4linux/nxc/responder (no SMB/Windows host)",
               "john/hashcat (no captured hashes)",
               "openvas/gvmd (Greenbone daemon inactive)"):
        skipped.append(na)

    a.findings = dedupe(a.findings)
    try:
        from . import cveintel
        cveintel.enrich_assessment(a)
    except Exception:  # noqa: BLE001 - enrichment must never break a scan
        pass
    a.finished = _iso()
    if skipped:
        a.notes = (a.notes or "") + "\n\n## Skipped / not applicable\n" + \
            "\n".join(f"- {s}" for s in skipped)
    a.report_md, a.report_json = report_mod.write_report(a, reports_dir)
    emit(type="scan_done", status="done", findings=a.summary(),
         report_md=a.report_md, report_json=a.report_json)
    return a
