"""CVE-focused vulnerability scanning: nuclei templates + nmap NSE ``vuln``.

Adds real CVE coverage to the framework:

* ``latest_cve_templates(n)`` selects the newest CVE templates by CVE id.
* ``run_cve_scan(target, severity="high,critical", latest=10)`` runs those
  templates plus a severity-wide sweep and nmap vuln scripts, then writes a
  review report.

All execution is scope-enforced (deny-by-default) and rate-limited.
"""

from __future__ import annotations

import json
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path

from . import findings as findings_mod
from . import jobs, memory, report as report_mod, runner, scope, waf
from .assess import redact_secrets as _base_redact

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = Path.home() / ".local" / "nuclei-templates"
DEFAULT_SEVERITY = "high,critical"

# Also redact env-style secrets embedded inside JSON (nuclei response bodies).
_EMBEDDED_SECRET_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE|"
    r"CREDENTIAL)[A-Z0-9_]*)=([^\s\\\"']{2,})"
)


def _mask(value: str) -> str:
    value = value.strip().strip('"').strip("'")
    return "**** [REDACTED]" if len(value) <= 4 else \
        f"{value[:2]}…{value[-2:]} [{len(value)} chars] [REDACTED]"


def redact(text: str) -> str:
    """Redact secrets in scanner output, including secrets embedded in JSON."""
    out = _base_redact(text or "")
    return _EMBEDDED_SECRET_RE.sub(
        lambda m: f"{m.group(1)}={_mask(m.group(2))}", out
    )


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "target"


def latest_cve_templates(n: int = 10) -> list[Path]:
    """Return the *n* most recent CVE templates (by CVE year + number)."""
    if n <= 0 or not TEMPLATES_DIR.exists():
        return []
    files = list(TEMPLATES_DIR.rglob("CVE-*.yaml"))

    def key(p: Path):
        m = re.search(r"CVE-(\d{4})-(\d+)", p.name)
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    files.sort(key=key)
    return files[-n:]


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------

def _nuclei_args(urls: list[str], *, severity: str | None = None,
                 templates: list[Path] | None = None, rate: int = 20,
                 concurrency: int = 10, timeout: int = 5,
                 extra: list[str] | None = None) -> list[str]:
    args = [
        "nuclei", "-jsonl", "-silent", "-no-interactsh",
        "-disable-update-check", "-rate-limit", str(rate),
        "-concurrency", str(concurrency), "-timeout", str(timeout),
        "-retries", "0", "-etags", "dos,fuzz",
    ]
    if severity:
        args += ["-severity", severity]
    for tpl in templates or []:
        args += ["-t", str(tpl)]
    for url in urls:
        args += ["-u", url]
    if extra:
        args += list(extra)
    return args


def parse_nuclei(text: str, target: str) -> list:
    """Parse nuclei JSONL output into findings."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue

        info = d.get("info") or {}
        sev = (info.get("severity") or "info").lower()
        if sev not in findings_mod.SEVERITIES:
            sev = "info"
        tid = d.get("template-id") or ""
        name = info.get("name") or tid or "nuclei finding"
        endpoint = d.get("matched-at") or d.get("host") or target

        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        cves = [str(c) for c in cves if c]
        cwe_ids = classification.get("cwe-id") or []
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]
        cwe_ids = [str(c) for c in cwe_ids if c]
        refs = list(info.get("reference") or [])
        refs += [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves]

        evidence = d.get("curl-command") or ""
        extracted = d.get("extracted-results") or []
        if extracted:
            evidence += "\nExtracted: " + ", ".join(map(str, extracted))
        if not evidence:
            evidence = json.dumps(d)[:1000]

        cvss = classification.get("cvss-score")
        cvss_vector = str(classification.get("cvss-metrics") or "")
        desc = info.get("description") or ""
        if cvss:
            desc = f"CVSS {cvss}. " + desc

        out.append(findings_mod.Finding(
            id=findings_mod._fid(f"{tid}{name}", endpoint, target),
            title=f"{tid} {name}".strip(),
            severity=sev,
            target=target,
            tool="nuclei",
            endpoint=endpoint,
            confidence="high",
            description=desc[:1000],
            evidence=redact(evidence[:2000]),
            remediation="Apply the vendor patch and upgrade to a fixed version.",
            references=[r for r in refs if r][:10],
            validation_status="scanner_match",
            cves=cves,
            cwe_ids=cwe_ids,
            cvss=_to_float(cvss),
            cvss_vector=cvss_vector,
        ))
    return out


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

def parse_nmap_vuln(text: str, target: str) -> list:
    out = []
    lines = (text or "").splitlines()
    for idx, raw in enumerate(lines):
        line = raw.strip()
        # Do not mistake prose that merely mentions "vulnerable" for a hit.
        # Nmap's standard vuln scripts report an explicit state or banner.
        if not re.search(r"\bState:\s*VULNERABLE\b", line, re.I) and not re.match(
            r"^[|_]\s*VULNERABLE:\s*", line, re.I
        ):
            continue
        title = line.lstrip("|_ ").strip() or "nmap vuln script finding"
        evidence_lines = [line]
        for following in lines[idx + 1:idx + 5]:
            if not following.startswith(("|", " ", "\t")):
                break
            evidence_lines.append(following.strip())
        out.append(findings_mod.Finding(
            id=findings_mod._fid("nmap-vuln " + title, target, target),
            title=f"nmap: {title[:120]}",
            severity="high",
            target=target,
            tool="nmap",
            endpoint=target,
            confidence="medium",
            description=("Nmap NSE reported an explicit VULNERABLE state. "
                         "Treat this as a scanner result requiring manual validation."),
            evidence="\n".join(evidence_lines)[:1500],
            remediation="Review the NSE script output and patch the affected service.",
            references=["https://nmap.org/nsedoc/categories/vuln.html"],
            validation_status="needs_manual_validation",
        ))
    return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class _Rec:
    def __init__(self, target: str, a: report_mod.Assessment, on_event=None):
        self.target = target
        self.a = a
        self.on_event = on_event

    def _emit(self, **ev):
        if self.on_event:
            try:
                self.on_event(**ev)
            except Exception:  # noqa: BLE001
                pass

    def execute(self, tool: str, argv: list[str], *, timeout: int,
                artifact: str, parser) -> runner.RunResult:
        self._emit(type="step_start", key=tool, label=tool, tool=tool,
                   agent="CVE Agent", timeout=timeout,
                   command=" ".join(shlex.quote(x) for x in argv))
        before = len(self.a.findings)
        try:
            # Nuclei responses can contain exposed credentials in HTTP bodies.
            # Capture without runner's raw artifact write, then persist only
            # redacted output below.
            result = runner.run(argv, timeout=timeout, artifact_name=None)
        except Exception as exc:  # noqa: BLE001
            self._emit(type="step_end", key=tool, label=tool,
                       agent="CVE Agent", status="error",
                       exit_code=None, duration_ms=None, findings=0)
            raise
        captured = result.stdout or ""
        if result.stderr:
            captured += "\n--- stderr ---\n" + result.stderr
        safe_captured = redact(captured)
        self.a.raw[tool] = safe_captured
        artifact_path = runner.ARTIFACT_DIR / Path(artifact).name
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(safe_captured, encoding="utf-8")
        result.artifact_path = str(artifact_path)
        self.a.commands.append({
            "tool": tool,
            "command": " ".join(shlex.quote(x) for x in argv),
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "artifact": result.artifact_path,
            "timeout": timeout,
        })
        self.a.artifacts.append(result.artifact_path)
        if parser is not None:
            self.a.findings.extend(parser(result.stdout or "", self.target))
        try:
            memory.memory.add_document(
                text=redact(result.stdout or ""),
                metadata={"tool": tool, "target": self.target,
                          "exit_code": result.exit_code},
            )
        except Exception:  # noqa: BLE001
            pass
        self._emit(type="step_end", key=tool, label=tool, agent="CVE Agent",
                   status=("done" if result.exit_code == 0 else "error"),
                   exit_code=result.exit_code, duration_ms=result.duration_ms,
                   findings=len(self.a.findings) - before)
        return result


def run_cve_scan(
    target: str,
    *,
    severity: str = DEFAULT_SEVERITY,
    latest: int = 10,
    rate: int | None = None,
    concurrency: int | None = None,
    nmap_vuln: bool = False,
    confirm_intrusive: bool = False,
    run_latest: bool = True,
    run_severity: bool = True,
    cmd_timeout: int = 1500,
    operator: str = "",
    reports_dir: Path | None = None,
    on_event=None,
    job_id: str | None = None,
    job_source: str = "cve",
) -> report_mod.Assessment:
    """Run a scope-checked CVE scan and write a report."""
    started = _iso()
    jid = jobs.create_job("cve", target, operator, source=job_source,
                          job_id=job_id, agent="CVE Agent")

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

    emit(type="scan_start", target=target, profile="cve", started=started)

    sc = scope.get_scope()
    allowed, reason = sc.check(target)
    a = report_mod.Assessment(
        target=target, profile="cve", authorized=allowed, scope_reason=reason,
        operator=operator, program=dict(sc.program), rules=dict(sc.rules),
        started=started,
    )
    a.job_id = jid
    if not allowed:
        a.finished = _iso()
        a.report_md, a.report_json = report_mod.write_report(a, reports_dir)
        emit(type="scan_done", status="denied", findings=a.summary(),
             report_md=a.report_md, report_json=a.report_json, error=reason)
        return a

    rules = sc.rules or {}
    rule_rate = int(rules.get("max_requests_per_second", 20) or 20)
    rule_concurrency = int(rules.get("max_concurrency", 10) or 10)
    requested_rate = rule_rate if rate is None else int(rate)
    requested_concurrency = rule_concurrency if concurrency is None else int(concurrency)
    if requested_rate <= 0 or requested_concurrency <= 0:
        raise ValueError("rate and concurrency must be positive")
    effective_rate = min(requested_rate, rule_rate)
    effective_concurrency = min(requested_concurrency, rule_concurrency)
    allowed_ports = [int(p) for p in (rules.get("allowed_ports") or [])]
    allowed_schemes = [str(s).lower() for s in
                       (rules.get("allowed_schemes") or ["https", "http"])]

    if nmap_vuln and not confirm_intrusive:
        emit(type="scan_error", error="nmap vuln scripts require explicit confirmation")
        raise PermissionError(
            "nmap --script vuln requires --nmap-vuln and --confirm-intrusive."
        )
    if nmap_vuln and not rules.get("allow_intrusive", False):
        emit(type="scan_error", error="scope rules disallow intrusive Nmap scripts")
        raise PermissionError(
            "scope.yaml rules.allow_intrusive must be true for Nmap vuln scripts."
        )

    host = scope.normalize_host(target)
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    urls: list[str] = []
    if allowed_ports:
        for port in allowed_ports:
            scheme = "https" if port in (443, 8443, 9443) else "http"
            if scheme not in allowed_schemes:
                continue
            default_port = (scheme == "https" and port == 443) or (
                scheme == "http" and port == 80
            )
            urls.append(f"{scheme}://{url_host}" + ("" if default_port else f":{port}"))
    else:
        urls = [f"{scheme}://{url_host}" for scheme in ("https", "http")
                if scheme in allowed_schemes]
    urls = list(dict.fromkeys(urls))
    if not urls:
        raise PermissionError("No target URLs remain after scope port/scheme restrictions.")

    # --- WAF / edge block preflight ----------------------------------
    # A block/challenge page would make nuclei/nmap report edge artifacts as
    # CVEs. Detect it first and report the scan as INCONCLUSIVE.
    user_agent = str(rules.get("user_agent") or "KaliPentestMCP/1.0")
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

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = _safe(host)
    rec = _Rec(target, a, on_event=emit)
    a.notes = (
        f"Effective nuclei limits: {effective_rate} requests/second, "
        f"{effective_concurrency} concurrent requests. Target URLs: "
        + ", ".join(urls)
        + (". Nmap vuln scripts skipped (explicit intrusive authorization required)."
           if not nmap_vuln else "")
    )

    plan = []
    if run_latest and latest:
        plan.append({"key": "nuclei-latest",
                     "label": f"nuclei (newest {latest} CVEs)",
                     "agent": "CVE Agent", "timeout": cmd_timeout})
    if run_severity and severity:
        plan.append({"key": "nuclei-severity",
                     "label": f"nuclei ({severity})", "agent": "CVE Agent",
                     "timeout": cmd_timeout})
    if nmap_vuln:
        plan.append({"key": "nmap-vuln", "label": "nmap --script vuln",
                     "agent": "CVE Agent", "timeout": min(cmd_timeout, 900)})
    emit(type="plan", steps=plan)

    # 1) latest N CVE templates
    if run_latest and latest:
        tpls = latest_cve_templates(latest)
        if tpls:
            argv = _nuclei_args(urls, templates=tpls, rate=effective_rate,
                                concurrency=effective_concurrency)
            rec.execute("nuclei-latest", argv, timeout=cmd_timeout,
                        artifact=f"{tag}_nuclei_latest{latest}_{stamp}.txt",
                        parser=parse_nuclei)

    # 2) severity-wide sweep (all templates)
    if run_severity and severity:
        argv = _nuclei_args(urls, severity=severity, rate=effective_rate,
                            concurrency=effective_concurrency)
        rec.execute("nuclei-severity", argv, timeout=cmd_timeout,
                    artifact=f"{tag}_nuclei_{severity}_{stamp}.txt",
                    parser=parse_nuclei)

    # 3) nmap NSE vuln scripts
    if nmap_vuln:
        argv = ["nmap", "-Pn", "-sV", "--script", "vuln", "--version-light",
                "--max-rate", str(effective_rate), "-T4", host]
        if allowed_ports:
            argv[argv.index("-T4"):argv.index("-T4")] = [
                "-p", ",".join(str(p) for p in allowed_ports)
            ]
        rec.execute("nmap-vuln", argv, timeout=min(cmd_timeout, 900),
                    artifact=f"{tag}_nmap_vuln_{stamp}.txt",
                    parser=parse_nmap_vuln)

    a.findings = findings_mod.dedupe(a.findings)
    try:
        from . import cveintel
        cveintel.enrich_assessment(a)
    except Exception:  # noqa: BLE001 - enrichment must never break a scan
        pass
    a.finished = _iso()
    a.report_md, a.report_json = report_mod.write_report(a, reports_dir)
    emit(type="scan_done", status="done", findings=a.summary(),
         report_md=a.report_md, report_json=a.report_json)
    return a
