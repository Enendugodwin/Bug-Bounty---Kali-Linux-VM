"""FastMCP server for the multi-agent, scope-enforced pentest framework."""

from __future__ import annotations

import shlex
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import assess as assess_mod
from . import cve as cve_mod
from . import jobs
from . import matrix as matrix_mod
from . import memory
from . import report as report_mod
from . import runner
from . import scope
from . import waf
from . import zap

mcp = FastMCP("Kali-Pentest-Advanced-Server")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
LOGS_DIR = PROJECT_ROOT / "logs"
REPORTS_DIR = PROJECT_ROOT / "reports"

# --- Tool Whitelists -------------------------------------------------------
AGENT_TOOLS = {
    "recon": ["nmap", "enum4linux", "dnsrecon", "dig"],
    "web": ["nikto", "gobuster", "ffuf", "wpscan", "sqlmap", "dirb",
            "whatweb", "wapiti"],
    "ad": ["nxc", "netexec", "impacket-psexec", "impacket-wmiexec",
           "crackmapexec", "responder"],
    "cracking": ["john", "hashcat"],
    "cve": ["nuclei", "nmap", "searchsploit"],
}
ALL_ALLOWED = [tool for tools in AGENT_TOOLS.values() for tool in tools]
INTRUSIVE_TOOLS = {
    "sqlmap", "responder", "nxc", "netexec", "crackmapexec",
    "impacket-psexec", "impacket-wmiexec",
}


# ---------------------------------------------------------------------------
# Generic runner
# ---------------------------------------------------------------------------

def _execute_tool(tool_name: str, target: str, options: str = "",
                  confirm_intrusive: bool = False) -> str:
    ok, reason = scope.check(target)
    if not ok:
        return f"Error: Target {target} is not authorized — {reason}"

    if tool_name not in ALL_ALLOWED:
        return f"Error: Tool {tool_name} is not allowed."

    if tool_name in INTRUSIVE_TOOLS:
        rules = scope.get_scope().rules
        if not confirm_intrusive:
            return (f"Refused: {tool_name} requires explicit confirm_intrusive=true "
                    "for this request.")
        if not rules.get("allow_intrusive", False):
            return "Refused: scope.yaml rules.allow_intrusive is false."

    cmd = [tool_name]
    if options:
        cmd.extend(shlex.split(options))
    cmd.append(target)

    agent = ("Recon Agent" if tool_name in {"nmap", "enum4linux", "dnsrecon", "dig"}
             else "Web Agent" if tool_name in {"nikto", "gobuster", "ffuf", "dirb", "wpscan", "whatweb", "wapiti"}
             else "CVE Agent" if tool_name in {"nuclei", "searchsploit"}
             else "Exploit Agent")
    jid = jobs.create_job("tool", target, source="mcp", agent=agent)
    jobs.record_event(jid, {"type": "scan_start", "target": target, "profile": "tool"})
    jobs.record_event(jid, {"type": "plan", "steps": [
        {"key": tool_name, "label": tool_name, "agent": agent}
    ]})
    jobs.record_event(jid, {"type": "step_start", "key": tool_name,
                            "label": tool_name, "agent": agent})
    try:
        result = runner.run(cmd)
        output = runner.to_text(result)
        memory.memory.add_document(
            text=result.stdout or "",
            metadata={"tool": tool_name, "target": target,
                      "exit_code": result.exit_code},
        )
        jobs.record_event(jid, {"type": "step_end", "key": tool_name,
                                "label": tool_name, "agent": agent,
                                "status": "done" if result.exit_code == 0 else "error",
                                "exit_code": result.exit_code,
                                "duration_ms": result.duration_ms,
                                "findings": 0})
        jobs.record_event(jid, {"type": "scan_done", "status": "done",
                                "findings": {"critical": 0, "high": 0,
                                             "medium": 0, "low": 0,
                                             "info": 0, "total": 0}})
        return f"Job ID: {jid}\n{output}"
    except Exception as exc:  # noqa: BLE001
        jobs.record_event(jid, {"type": "scan_error",
                                "error": f"{type(exc).__name__}: {exc}"})
        return f"Execution error: {exc}"


# ---------------------------------------------------------------------------
# Scope tools
# ---------------------------------------------------------------------------

@mcp.tool()
def scope_info() -> str:
    """Show the active authorized scope, exclusions, and rules of engagement."""
    sc = scope.get_scope(force=True)
    lines = [f"Scope source: {sc.source}"]
    if sc.program:
        lines.append(f"Program: {sc.program.get('name', '—')}")
        lines.append(f"Authorization: {sc.program.get('authorization', '—')}")
    if sc.rules:
        lines.append("Rules: " + ", ".join(f"{k}={v}" for k, v in sc.rules.items()))
    lines.append("In scope: " + (", ".join(sc.entries()) or "(none)"))
    excluded = [f"domain:{d}" for d in sc.ex_domains]
    excluded += [f"wildcard:{w}" for w in sc.ex_wildcards]
    excluded += [f"ip:{i}" for i in sc.ex_ips]
    excluded += [f"cidr:{c}" for c in sc.ex_cidrs]
    excluded += [f"path:{p}" for p in sc.ex_paths]
    lines.append("Excluded: " + (", ".join(excluded) or "(none)"))
    return "\n".join(lines)


@mcp.tool()
def scope_check(target: str) -> str:
    """Check whether a target is authorized before any testing."""
    ok, reason = scope.check(target)
    return f"{'AUTHORIZED' if ok else 'DENIED'}: {target} — {reason}"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@mcp.tool()
def assess_target(target: str, profile: str = "web", operator: str = "",
                  dry_run: bool = False) -> str:
    """Run a full scope-checked assessment and write a review report.

    profile: web | network | full. Refuses to touch out-of-scope targets.
    """
    a = assess_mod.run_assessment(
        target, profile=profile, operator=operator, dry_run=dry_run,
        job_source="mcp",
    )
    if not a.authorized:
        return f"Refused: {a.target} — {a.scope_reason}"

    s = a.summary()
    out = [
        f"Assessment of {a.target} ({a.profile}) complete.",
        f"Scope: {a.scope_reason}",
        f"Job ID: {a.job_id}",
        "Findings: " + ", ".join(
            f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
        ) + f", total={s['total']}",
        f"Commands run: {len(a.commands)}",
    ]
    if a.report_md:
        out.append(f"Report (Markdown): {a.report_md}")
        out.append(f"Report (JSON): {a.report_json}")
    if dry_run:
        out.append("(dry run — nothing executed)")
    return "\n".join(out)


@mcp.tool()
def cve_agent(target: str, severity: str = "high,critical",
              latest: int = 10) -> str:
    """Run a CVE scan (nuclei templates + nmap vuln scripts).

    Runs the newest N CVE templates plus a severity-wide sweep. Scope-enforced.
    """
    a = cve_mod.run_cve_scan(target, severity=severity, latest=latest,
                             job_source="mcp")
    if not a.authorized:
        return f"Refused: {a.target} — {a.scope_reason}"
    s = a.summary()
    out = [
        f"CVE scan of {a.target} complete.",
        f"Job ID: {a.job_id}",
        "Findings: " + ", ".join(
            f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
        ) + f", total={s['total']}",
    ]
    for c in a.commands:
        out.append(f"  - [{c.get('exit_code')}] {c.get('command')[:150]}")
    if a.report_md:
        out.append(f"Report (Markdown): {a.report_md}")
        out.append(f"Report (JSON): {a.report_json}")
    return "\n".join(out)


@mcp.tool()
def matrix_agent(target: str, operator: str = "",
                 include_intrusive: bool = False,
                 confirm_intrusive: bool = False) -> str:
    """Run the full matrix. SQLMap requires both explicit flags and scope authorization."""
    try:
        a = matrix_mod.run_matrix(
            target, operator=operator, include_intrusive=include_intrusive,
            confirm_intrusive=confirm_intrusive, job_source="mcp",
        )
    except PermissionError as exc:
        return f"Refused: {exc}"
    if not a.authorized:
        return f"Refused: {a.target} — {a.scope_reason}"
    s = a.summary()
    out = [
        f"Matrix scan of {a.target} complete.",
        f"Job ID: {a.job_id}",
        "Findings: " + ", ".join(
            f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
        ) + f", total={s['total']}",
    ]
    for c in a.commands:
        out.append(f"  - [{c.get('exit_code')}] {c.get('command')[:120]}")
    if a.report_md:
        out.append(f"Report (Markdown): {a.report_md}")
        out.append(f"Report (JSON): {a.report_json}")
    return "\n".join(out)


@mcp.tool()
def planner(goal: str, target: str = "", profile: str = "web") -> str:
    """Produce a scoped execution plan for a high-level goal."""
    scope_line = ""
    if target:
        ok, reason = scope.check(target)
        scope_line = (
            f"\nScope check for {target}: "
            f"{'AUTHORIZED' if ok else 'DENIED'} — {reason}\n"
        )
    return (
        f"Plan for goal: {goal}{scope_line}\n"
        f"1. Scope gate: verify {target or 'target'} in scope.yaml (deny-by-default).\n"
        f"2. Recon: nmap service scan; pivot to enum4linux on Windows/SMB.\n"
        f"3. Web ({profile}): if 80/443 open, nikto baseline + gobuster discovery.\n"
        f"4. Findings: normalize output into severity-ranked findings.\n"
        f"5. Report: write reports/<target>.md + .json for human review.\n"
        f"Use assess_target(target='{target or '<target>'}', profile='{profile}') "
        f"to execute steps 1-5."
    )


# ---------------------------------------------------------------------------
# Agents (raw tool wrappers, still scope-enforced)
# ---------------------------------------------------------------------------

@mcp.tool()
def recon_agent(target: str, options: str = "") -> str:
    """Network reconnaissance via nmap; enum4linux when Windows is detected."""
    res = _execute_tool("nmap", target, options or "-F")
    if "microsoft" in res.lower() or "windows" in res.lower():
        res += "\n\n[!] Windows detected. Running enum4linux...\n"
        res += _execute_tool("enum4linux", target, "")
    return res


@mcp.tool()
def web_agent(target: str, options: str = "") -> str:
    """Web application testing via nikto (with sensible default tuning)."""
    ok, reason = scope.check(target)
    if not ok:
        return f"Error: Target {target} is not authorized — {reason}"

    opts = shlex.split(options) if options else []
    if "-Tuning" not in opts:
        opts += ["-Tuning", "1"]

    cmd = ["nikto", "-h", target, *opts]
    jid = jobs.create_job("tool", target, source="mcp", agent="Web Agent")
    jobs.record_event(jid, {"type": "scan_start", "target": target, "profile": "tool"})
    jobs.record_event(jid, {"type": "plan", "steps": [
        {"key": "nikto", "label": "nikto", "agent": "Web Agent"}
    ]})
    jobs.record_event(jid, {"type": "step_start", "key": "nikto",
                            "label": "nikto", "agent": "Web Agent"})
    try:
        result = runner.run(cmd)
        output = runner.to_text(result)
        memory.memory.add_document(
            text=result.stdout or "",
            metadata={"tool": "nikto", "target": target},
        )
        jobs.record_event(jid, {"type": "step_end", "key": "nikto",
                                "label": "nikto", "agent": "Web Agent",
                                "status": "done" if result.exit_code == 0 else "error",
                                "exit_code": result.exit_code,
                                "duration_ms": result.duration_ms,
                                "findings": 0})
        jobs.record_event(jid, {"type": "scan_done", "status": "done",
                                "findings": {"critical": 0, "high": 0,
                                             "medium": 0, "low": 0,
                                             "info": 0, "total": 0}})
        return f"Job ID: {jid}\n{output}"
    except Exception as exc:  # noqa: BLE001
        jobs.record_event(jid, {"type": "scan_error",
                                "error": f"{type(exc).__name__}: {exc}"})
        return f"Execution error: {exc}"


@mcp.tool()
def ad_agent(target: str, options: str = "",
             confirm_intrusive: bool = False) -> str:
    """AD enumeration requires explicit confirmation and allow_intrusive scope authorization."""
    sc = scope.get_scope()
    if not confirm_intrusive:
        return "Refused: AD tooling requires confirm_intrusive=true for this request."
    if not sc.rules.get("allow_intrusive", False):
        return (
            "AD/network attack tooling is disabled: scope rules set "
            "allow_intrusive=false. Enable it in scope.yaml only for an "
            "engagement that explicitly authorizes it."
        )
    return _execute_tool("nxc", target, options or "smb",
                         confirm_intrusive=confirm_intrusive)


@mcp.tool()
def run_security_tool(tool_name: str, target: str, options: str = "",
                      confirm_intrusive: bool = False) -> str:
    """Run a whitelisted tool; intrusive tools require explicit confirmation."""
    return _execute_tool(tool_name, target, options,
                         confirm_intrusive=confirm_intrusive)


# ---------------------------------------------------------------------------
# WAF exposure
# ---------------------------------------------------------------------------

@mcp.tool()
def waf_check(target: str) -> str:
    """Detect a WAF and flag origin-IP exposure for a scope-authorized target.

    Reports whether a WAF is present (and which vendor) and whether the
    target's origin IP is directly reachable — which would mean the WAF can
    likely be bypassed. The origin probe only runs when the resolved IP is
    itself authorized by scope.yaml.
    """
    report = waf.run_waf_check(target, job_source="mcp")
    text = report.to_text()
    if report.authorized and report.job_id:
        text = f"Job ID: {report.job_id}\n{text}"
    return text


# ---------------------------------------------------------------------------
# OWASP ZAP (scope-gated)
# ---------------------------------------------------------------------------

@mcp.tool()
def zap_spider(target: str) -> str:
    """Spider an authorized target with ZAP, restricted to its host."""
    report = zap.run_spider(target, job_source="mcp")
    text = report.to_text()
    if report.authorized and report.job_id:
        text = f"Job ID: {report.job_id}\n{text}"
    return text


@mcp.tool()
def zap_alerts(target: str) -> str:
    """Read ZAP alerts recorded for an authorized target."""
    report = zap.run_alerts(target, job_source="mcp")
    return report.to_text()


@mcp.tool()
def zap_active_scan(target: str, confirm_active: bool = False) -> str:
    """Active scan with ZAP. Requires confirm_active=true AND rules.allow_active_scan."""
    report = zap.run_active_scan(target, confirm_active=confirm_active,
                                 job_source="mcp")
    text = report.to_text()
    if report.authorized and report.job_id:
        text = f"Job ID: {report.job_id}\n{text}"
    return text


# ---------------------------------------------------------------------------
# Reporting & memory
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_findings_report() -> str:
    """Render the most recent assessment report, or synthesize one from artifacts."""
    jsons = sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if jsons:
        a = report_mod.load_assessment(jsons[-1])
        return report_mod.render_markdown(a)

    artifacts = list(ARTIFACTS_DIR.glob("*.txt"))
    audit_log = LOGS_DIR / "audit.log"
    parts = ["# Automated Security Findings Report\n", "## Execution History\n"]
    parts.append(audit_log.read_text(encoding="utf-8") if audit_log.exists()
                 else "No audit logs found.\n")
    parts.append("\n## Artifact Analysis\n")
    for art in artifacts:
        parts.append(f"### {art.name}\n```text\n{art.read_text(encoding='utf-8')}\n```\n")
    return "\n".join(parts)


@mcp.tool()
def query_past_scans(query: str) -> str:
    """Search previous scan results (RAG) for similar patterns or findings."""
    results = memory.memory.query(query)
    if not results:
        return "No similar previous scans found in memory."
    out = ["### Relevant Past Findings:"]
    for i, res in enumerate(results):
        doc = res["document"]
        out.append(f"\n**Result {i+1} (Similarity: {res['score']:.2f})**")
        out.append(f"Tool: {doc['metadata'].get('tool')} | "
                   f"Target: {doc['metadata'].get('target')}")
        out.append(f"Findings: {doc['text'][:500]}...")
    return "\n".join(out)


if __name__ == "__main__":
    mcp.run()
