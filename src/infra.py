"""Infrastructure assessment: firewalls, Windows/AD, switches and Linux/Unix.

Service-driven: ``nmap`` discovers open ports, then asset-class-appropriate,
scope-checked tools run against what was found:

* **Windows / AD / SMB**  — ``enum4linux-ng``, ``nxc``/``netexec`` (smb, ldap,
  winrm), ``smbclient``/``rpcclient`` (via nxc), nmap NSE.
* **RDP**                  — nmap ``rdp-enum-encryption`` / ``rdp-ntlm-info``.
* **Linux / Unix / SSH**   — nmap ``ssh2-enum-algos`` / ``ssh-auth-methods``.
* **Switches / gear / SNMP** — ``onesixtyone`` (community strings) + ``snmpwalk``.
* **NFS / RPC**            — ``showmount``, nmap ``rpc``-family scripts.
* **Firewalls / VPN**      — ``ike-scan`` (IKE/IPsec), nmap ``ssl-enum-ciphers``.
* **Management TLS**       — ``sslscan``.

Safety
------
Deny-by-default scope is enforced before anything runs. Credential attacks
(``hydra``, ``evil-winrm``) and nmap ``--script vuln``/``auth`` are **off** and
require both ``allow_intrusive: true`` in ``scope.yaml`` and an explicit
``--confirm-intrusive`` per invocation.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import findings as findings_mod
from . import jobs, memory, report as report_mod, runner, scope
from .cve import parse_nmap_vuln
from .findings import Finding, dedupe, parse_output

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = PROJECT_ROOT / "artifacts"

AGENT = "Infra Agent"

# A curated service set covering the four asset classes (fast with -sV).
INFRA_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900,
    5985, 5986, 6379, 8080, 8443, 9200, 11211, 27017,
]

_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)

# Ports -> asset class label, for reporting.
_CLASS = {
    445: "SMB/Windows", 139: "SMB/Windows", 135: "Windows RPC",
    389: "LDAP/AD", 636: "LDAPS/AD", 88: "Kerberos/AD",
    3389: "RDP", 5985: "WinRM", 5986: "WinRM (TLS)",
    22: "SSH/Linux", 111: "RPC/NFS", 2049: "NFS",
    161: "SNMP/network-gear",
    500: "IKE/VPN", 4500: "IKE/VPN",
    443: "TLS/mgmt", 8443: "TLS/mgmt", 993: "TLS/mgmt", 995: "TLS/mgmt",
}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(t: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", t).strip("_") or "target"


def _open_services(nmap_stdout: str) -> dict[int, str]:
    """Return ``{port: service}`` from nmap ``-sV`` output."""
    services: dict[int, str] = {}
    for port, svc, _version in _PORT_RE.findall(nmap_stdout or ""):
        services[int(port)] = svc.lower().rstrip("?")
    return services


# ---------------------------------------------------------------------------
# Parsers (each is defensive and never raises)
# ---------------------------------------------------------------------------

def _mk(title, severity, target, tool, **kw) -> Finding:
    endpoint = kw.pop("endpoint", target)
    return Finding(
        id=findings_mod._fid(title, endpoint, target),
        title=title, severity=severity, target=target, tool=tool,
        endpoint=endpoint, **kw,
    )


def parse_nmap_nse(stdout: str, target: str) -> list[Finding]:
    """Turn nmap NSE ``|`` output lines into informational findings."""
    seen: set[str] = set()
    out: list[Finding] = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        body = line.lstrip("|_ ").strip()
        if not body or body in seen:
            continue
        seen.add(body)
        out.append(_mk(f"nmap NSE: {body[:100]}", "info", target, "nmap",
                       confidence="medium", description=body[:400],
                       evidence=line, remediation="Review the service configuration."))
    return out


def parse_enum4linux_ng(path: str | Path, target: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return out
    if not isinstance(data, dict):
        return out

    users = data.get("users") or {}
    if isinstance(users, list):
        users = {str(u): {} for u in users}
    if users:
        names = ", ".join(list(users)[:20])
        out.append(_mk(
            f"SMB/AD users enumerated ({len(users)})", "low", target,
            "enum4linux-ng", endpoint=target, confidence="medium",
            description=f"Enumeration returned {len(users)} account name(s).",
            evidence=names[:1500],
            remediation="Restrict anonymous/guest SMB enumeration.",
            references=["https://github.com/cddmp/enum4linux-ng"],
        ))

    shares = data.get("shares") or {}
    if isinstance(shares, dict):
        readable = [name for name, meta in shares.items()
                    if isinstance(meta, dict)
                    and str(meta.get("access", "")).strip() not in ("", "DENIED")]
        readable = readable or list(shares)
        if readable:
            out.append(_mk(
                f"SMB shares enumerated ({len(shares)})", "low", target,
                "enum4linux-ng", endpoint=target, confidence="medium",
                description="SMB shares were listed without credentials.",
                evidence=", ".join(readable[:20])[:1500],
                remediation="Require authentication and review share permissions.",
                references=["https://github.com/cddmp/enum4linux-ng"],
            ))
    return out


def parse_nxc(stdout: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if "[+]" not in line and "signing" not in line.lower() and "SMBv1" not in line:
            continue
        low = line.lower()
        if "signing:false" in low:
            out.append(_mk("SMB signing not required", "medium", target, "nxc",
                           confidence="high", description=line[:400],
                           evidence=line,
                           remediation="Require SMB signing to prevent relay attacks.",
                           references=["https://www.netexec.wiki/"]))
        elif "smbv1" in low:
            out.append(_mk("SMBv1 enabled", "medium", target, "nxc",
                           confidence="medium", description=line[:400],
                           evidence=line,
                           remediation="Disable SMBv1 on the host.",
                           references=["https://www.netexec.wiki/"]))
        elif "[+]" in line:
            out.append(_mk(f"nxc: {line[:100]}", "low", target, "nxc",
                           confidence="medium", description=line[:400],
                           evidence=line, remediation="Review the exposed service.",
                           references=["https://www.netexec.wiki/"]))
    return out


def parse_onesixtyone(stdout: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    rx = re.compile(r"(\S+)\s+\[([^\]]+)\]")
    for raw in (stdout or "").splitlines():
        m = rx.search(raw.strip())
        if not m:
            continue
        host, community = m.group(1), m.group(2)
        sev = "medium" if community.lower() in ("public", "private") else "low"
        out.append(_mk(
            f"SNMP community string '{community}' accepted", sev, target,
            "onesixtyone", endpoint=host, confidence="high",
            description="The device answered SNMP requests with this community string.",
            evidence=raw.strip(),
            remediation="Use a strong SNMPv3 credential and restrict SNMP access.",
            references=["https://github.com/trailofbits/onesixtyone"],
            validation_status="scanner_match",
        ))
    return out


def parse_snmpwalk(stdout: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    for key, label in (("sysDescr.0", "SNMP sysDescr disclosed"),
                       ("sysName.0", "SNMP sysName disclosed")):
        m = re.search(re.escape(key) + r"\s*=\s*(?:STRING|OID|Hex-STRING):\s*(.+)",
                      stdout or "")
        if not m:
            continue
        out.append(_mk(
            label, "low", target, "snmpwalk", confidence="high",
            description=f"{key} is readable over SNMP.",
            evidence=m.group(0).strip()[:400],
            remediation="Restrict SNMP to trusted management hosts (SNMPv3, ACLs).",
            references=["https://www.net-snmp.org/"],
        ))
    return out


def parse_showmount(stdout: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("Export list"):
            continue
        export = line.split()[0]
        if not export.startswith("/"):
            continue
        out.append(_mk(
            f"NFS export exposed: {export}", "medium", target, "showmount",
            confidence="high",
            description="An NFS export is listable without authentication.",
            evidence=line[:400],
            remediation="Restrict NFS exports by host and prefer Kerberos/NFSv4.",
            references=["https://www.cisa.gov/secure-our-world"],
        ))
    return out


def parse_ikescan(stdout: str, target: str) -> list[Finding]:
    if not re.search(r"(handshake|SA=|vendor|transforms)", stdout or "", re.I):
        return []
    return [_mk(
        "IKE/IPsec endpoint responded", "info", target, "ike-scan",
        confidence="medium",
        description="The host answers IKE (UDP/500) — a firewall/VPN gateway.",
        evidence=(stdout or "").strip()[:600],
        remediation="Confirm the VPN gateway is intended to be internet-facing.",
        references=["https://github.com/royhills/ike-scan"],
    )]


def parse_sslscan(stdout: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    weak = [p for p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
            if re.search(r"\b" + re.escape(p) + r"\b", stdout or "")
            and re.search(r"(enabled|accepted|offered)", stdout or "", re.I)]
    if weak:
        out.append(_mk(
            "Weak TLS protocols offered: " + ", ".join(weak), "medium", target,
            "sslscan", confidence="medium",
            description="The management interface negotiates deprecated TLS versions.",
            evidence=", ".join(weak),
            remediation="Disable TLS < 1.2 on the management interface.",
            references=["https://github.com/rbsec/sslscan"],
        ))
    return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def _run(a: report_mod.Assessment, target: str, emit, tool: str, argv: list[str],
         *, timeout: int, artifact: str, base_url: str = "",
         key: str | None = None, label: str | None = None,
         parser=None, file_parser=None, parse_file: Path | None = None):
    k = key or tool
    lbl = label or tool
    if shutil.which(argv[0]) is None:
        emit(type="step_skipped", key=k, label=lbl, agent=AGENT,
             reason="not installed")
        return None
    emit(type="step_start", key=k, label=lbl, tool=tool, agent=AGENT,
         timeout=timeout, command=" ".join(shlex.quote(x) for x in argv))
    before = len(a.findings)
    try:
        res = runner.run(argv, timeout=timeout, artifact_name=artifact)
    except Exception as exc:  # noqa: BLE001
        emit(type="step_end", key=k, label=lbl, agent=AGENT, status="error",
             exit_code=None, duration_ms=None, findings=0)
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
    a.raw[lbl] = captured[:20000]
    if file_parser is not None and parse_file is not None and Path(parse_file).exists():
        a.findings.extend(file_parser(parse_file, target))
    if parser is not None:
        a.findings.extend(parser(res.stdout or "", target))
    try:
        memory.memory.add_document(
            text=res.stdout or "",
            metadata={"tool": tool, "target": target, "exit_code": res.exit_code},
        )
    except Exception:  # noqa: BLE001
        pass
    emit(type="step_end", key=k, label=lbl, agent=AGENT,
         status=("done" if res.exit_code == 0 else "error"),
         exit_code=res.exit_code, duration_ms=res.duration_ms,
         findings=len(a.findings) - before)
    return res


def run_infra(
    target: str,
    *,
    operator: str = "",
    rate: int = 20,
    cmd_timeout: int = 900,
    include_intrusive: bool = False,
    confirm_intrusive: bool = False,
    reports_dir: Path | None = None,
    on_event=None,
    job_id: str | None = None,
    job_source: str = "infra",
) -> report_mod.Assessment:
    """Run a scope-enforced infrastructure assessment."""
    started = _iso()
    jid = jobs.create_job("infra", target, operator, source=job_source,
                          job_id=job_id, agent=AGENT)

    def emit(**ev):
        try:
            jobs.record_event(jid, ev)
        except Exception:  # noqa: BLE001
            pass
        if on_event:
            try:
                on_event(ev)
            except Exception:  # noqa: BLE001
                pass

    emit(type="scan_start", target=target, profile="infra", started=started)

    sc = scope.get_scope()
    allowed, reason = sc.check(target)
    a = report_mod.Assessment(
        target=target, profile="infra", authorized=allowed, scope_reason=reason,
        operator=operator, program=dict(sc.program), rules=dict(sc.rules),
        started=started,
    )
    a.job_id = jid
    if not allowed:
        a.scan_status = "denied"
        a.finished = _iso()
        a.report_md, a.report_json = report_mod.write_report(a, reports_dir)
        emit(type="scan_done", status="denied", findings=a.summary(),
             report_md=a.report_md, report_json=a.report_json, error=reason)
        return a

    if include_intrusive and not confirm_intrusive:
        emit(type="scan_error", error="Intrusive infra tooling requires confirmation.")
        raise PermissionError(
            "Intrusive infra tooling requires --intrusive and --confirm-intrusive."
        )
    if include_intrusive and not sc.rules.get("allow_intrusive", False):
        emit(type="scan_error", error="scope rules disallow intrusive testing")
        raise PermissionError(
            "scope.yaml rules.allow_intrusive must be true for intrusive infra tools."
        )

    host = scope.normalize_host(target)
    rules = sc.rules or {}
    rule_rate = int(rules.get("max_requests_per_second", 20) or 20)
    eff_rate = min(int(rate or rule_rate), rule_rate)
    allowed_ports = [int(p) for p in (rules.get("allowed_ports") or [])]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = _safe(host)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    skipped: list[str] = []

    def art(name: str) -> str:
        return f"{tag}_{name}_{stamp}.txt"

    def jfile(name: str) -> Path:
        return ARTIFACTS / f"{tag}_{name}_{stamp}.json"

    ports = allowed_ports or INFRA_PORTS
    emit(type="plan", steps=[
        {"key": "nmap", "label": "nmap service discovery", "agent": AGENT,
         "timeout": 300},
    ])

    nmap = _run(
        a, host, emit, "nmap",
        ["nmap", "-Pn", "-sV", "--version-light", "-T4",
         "--max-rate", str(max(20, eff_rate * 5)),
         "--max-retries", "2", "--host-timeout", "120s",
         "-p", ",".join(str(p) for p in ports), host],
        timeout=300, artifact=art("nmap_infra"), key="nmap",
        parser=lambda t, tg: parse_output("nmap", t, tg),
    )
    services = _open_services(nmap.stdout if nmap else "")
    if not services:
        a.notes = (a.notes or "") + "\n\nNo open TCP services discovered on the " \
            "curated port set."

    want = lambda *ps: any(p in services for p in ps)  # noqa: E731
    classes = sorted({_CLASS[p] for p in services if p in _CLASS})

    # --- Windows / SMB / AD -------------------------------------------
    if want(135, 139, 445):
        out = jfile("enum4linux")
        _run(a, host, emit, "enum4linux-ng",
             ["enum4linux-ng", "-A", "-oJ", str(out), host],
             timeout=min(cmd_timeout, 400), artifact=art("enum4linux"),
             key="enum4linux", label="enum4linux-ng",
             file_parser=parse_enum4linux_ng, parse_file=out)
        _run(a, host, emit, "nxc",
             ["nxc", "smb", host, "--shares", "--users", "--groups"],
             timeout=min(cmd_timeout, 300), artifact=art("nxc_smb"),
             key="nxc-smb", label="nxc smb", parser=parse_nxc)
    if want(389, 636):
        _run(a, host, emit, "nxc",
             ["nxc", "ldap", host], timeout=min(cmd_timeout, 300),
             artifact=art("nxc_ldap"), key="nxc-ldap", label="nxc ldap",
             parser=parse_nxc)
    if want(5985, 5986):
        _run(a, host, emit, "nxc",
             ["nxc", "winrm", host], timeout=min(cmd_timeout, 300),
             artifact=art("nxc_winrm"), key="nxc-winrm", label="nxc winrm",
             parser=parse_nxc)
    if want(3389):
        _run(a, host, emit, "nmap",
             ["nmap", "-Pn", "-p", "3389", "--script",
              "rdp-enum-encryption,rdp-ntlm-info", host],
             timeout=180, artifact=art("nmap_rdp"), key="nmap-rdp",
             label="nmap rdp", parser=parse_nmap_nse)
    # --- Linux / SSH ---------------------------------------------------
    if want(22):
        _run(a, host, emit, "nmap",
             ["nmap", "-Pn", "-p", "22", "--script",
              "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey", host],
             timeout=180, artifact=art("nmap_ssh"), key="nmap-ssh",
             label="nmap ssh", parser=parse_nmap_nse)
    # --- NFS / RPC -----------------------------------------------------
    if want(111, 2049):
        _run(a, host, emit, "showmount", ["showmount", "-e", host],
             timeout=90, artifact=art("showmount"), key="showmount",
             parser=parse_showmount)
    # --- SNMP (switches / network gear) --------------------------------
    if want(161):
        _run(a, host, emit, "onesixtyone",
             ["onesixtyone", "-c", "/usr/share/seclists/Discovery/SNMP/"
              "snmp-onesixtyone.txt", host]
             if Path("/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt").exists()
             else ["onesixtyone", host],
             timeout=120, artifact=art("onesixtyone"), key="onesixtyone",
             parser=parse_onesixtyone)
        _run(a, host, emit, "snmpwalk", ["snmpwalk", "-v2c", "-c", "public",
                                          host, "system"],
             timeout=120, artifact=art("snmpwalk"), key="snmpwalk",
             parser=parse_snmpwalk)
    # --- Firewalls / VPN ----------------------------------------------
    if want(500, 4500):
        _run(a, host, emit, "ike-scan", ["ike-scan", host],
             timeout=120, artifact=art("ikescan"), key="ike-scan",
             parser=parse_ikescan)
    # --- Management TLS -----------------------------------------------
    tls_ports = [p for p in services if p in (443, 8443, 993, 995)]
    if tls_ports:
        _run(a, host, emit, "sslscan",
             ["sslscan", "--no-colour", host], timeout=300,
             artifact=art("sslscan"), key="sslscan", parser=parse_sslscan)

    # --- Intrusive (explicitly gated) ---------------------------------
    if include_intrusive:
        _run(a, host, emit, "nmap",
             ["nmap", "-Pn", "-sV", "--script", "vuln", "-T4", host],
             timeout=min(cmd_timeout, 900), artifact=art("nmap_vuln"),
             key="nmap-vuln", label="nmap vuln", parser=parse_nmap_vuln)
    else:
        skipped.append("nmap --script vuln (requires --intrusive --confirm-intrusive)")
        skipped.append("hydra / evil-winrm / credential attacks (intrusive)")
        emit(type="step_skipped", key="intrusive", label="intrusive tools",
             agent=AGENT, reason="explicit intrusive confirmation not supplied")

    a.findings = dedupe(a.findings)
    try:
        from . import cveintel
        cveintel.enrich_assessment(a)
    except Exception:  # noqa: BLE001
        pass
    a.finished = _iso()

    summary_bits = []
    if classes:
        summary_bits.append("Asset classes: " + ", ".join(classes))
    if services:
        summary_bits.append("Open services: " + ", ".join(
            f"{p}/{services[p]}" for p in sorted(services)))
    if summary_bits:
        a.notes = "\n\n".join(summary_bits) + ("\n\n" + a.notes if a.notes else "")
    if skipped:
        a.notes = (a.notes or "") + "\n\n## Skipped / gated\n" + \
            "\n".join(f"- {s}" for s in dict.fromkeys(skipped))

    a.report_md, a.report_json = report_mod.write_report(a, reports_dir)
    emit(type="scan_done", status="done", findings=a.summary(),
         report_md=a.report_md, report_json=a.report_json)
    return a
