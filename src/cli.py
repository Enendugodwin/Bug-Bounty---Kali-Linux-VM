"""Command-line interface for the Kali Pentest MCP bug-bounty framework.

Examples
--------
  python -m src.cli scope
  python -m src.cli scope-check www.vulnbank.org
  python -m src.cli assess www.vulnbank.org --profile web --dry-run
  python -m src.cli assess www.vulnbank.org --profile web --operator alice
  python -m src.cli report --latest
  python -m src.cli serve
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import assess as assess_mod
from . import cve as cve_mod
from . import infra as infra_mod
from . import intrusive as intrusive_mod
from . import matrix as matrix_mod
from . import report as report_mod
from . import scope as scope_mod


def _cmd_scope(args) -> int:
    sc = scope_mod.get_scope(force=True)
    print(f"Scope source : {sc.source}")
    if sc.program:
        print(f"Program      : {sc.program.get('name', '—')}")
        print(f"Authorization: {sc.program.get('authorization', '—')}")
    if sc.rules:
        print("Rules        : " + ", ".join(f"{k}={v}" for k, v in sc.rules.items()))
    print("\nIn scope:")
    for e in sc.entries() or ["(none)"]:
        print(f"  - {e}")
    ex = []
    ex += [f"domain:{d}" for d in sc.ex_domains]
    ex += [f"wildcard:{w}" for w in sc.ex_wildcards]
    ex += [f"ip:{i}" for i in sc.ex_ips]
    ex += [f"cidr:{c}" for c in sc.ex_cidrs]
    ex += [f"path:{p}" for p in sc.ex_paths]
    print("\nExcluded:")
    for e in ex or ["(none)"]:
        print(f"  - {e}")
    return 0


def _cmd_scope_check(args) -> int:
    ok, reason = scope_mod.check(args.target)
    status = "AUTHORIZED" if ok else "DENIED"
    print(f"[{status}] {args.target} — {reason}")
    return 0 if ok else 2


def _cmd_assess(args) -> int:
    a = assess_mod.run_assessment(
        args.target,
        profile=args.profile,
        operator=args.operator or "",
        wordlist=args.wordlist,
        deep=args.deep,
        nuclei=args.nuclei or args.deep,
        cve_intel=not args.no_cve_intel,
        dry_run=args.dry_run,
        all_web_ports=args.all_ports,
        nikto_maxtime=args.nikto_maxtime,
        ignore_block=args.ignore_block,
        write_report=not args.no_report,
        reports_dir=Path(args.report_dir) if args.report_dir else None,
        job_source="cli",
    )

    if args.json:
        print(json.dumps(a.to_json(), indent=2))
        return 0 if a.authorized else 2

    print(f"\n=== Assessment: {a.target} ({a.profile}) ===")
    print(f"Scope     : {'AUTHORIZED' if a.authorized else 'DENIED'} — {a.scope_reason}")
    if not a.authorized:
        return 2

    s = a.summary()
    print("Findings  : "
          + ", ".join(f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info"))
          + f", total={s['total']}")
    if a.job_id:
        print(f"Job ID    : {a.job_id}")
    print(f"Commands  : {len(a.commands)}")
    for c in a.commands:
        print(f"  - [{c.get('exit_code')}] {c.get('command')}")
    if a.artifacts:
        print("Artifacts :")
        for art in a.artifacts:
            print(f"  - {art}")

    if args.dry_run:
        print("Report    : (dry run — not written)")
        return 0

    print(f"Report    : {a.report_md or '(not written)'}")
    print(f"JSON      : {a.report_json or '(not written)'}")
    return 0


def _cmd_report(args) -> int:
    reports = report_mod.REPORTS_DIR
    jsons = sorted(reports.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not jsons:
        print("No assessment JSON files found in", reports)
        return 1
    path = Path(args.path) if args.path else jsons[-1]
    a = report_mod.load_assessment(path)
    md, js = report_mod.write_report(a, path.parent)
    print(f"Regenerated report for {a.target}")
    print(f"  Markdown: {md}")
    print(f"  JSON    : {js}")
    return 0


def _cmd_enrich(args) -> int:
    path = Path(args.path) if args.path else None
    if path is None or not path.exists():
        jsons = sorted(report_mod.REPORTS_DIR.glob("*.json"),
                       key=lambda p: p.stat().st_mtime)
        if not jsons:
            print("No assessment JSON files found in", report_mod.REPORTS_DIR)
            return 1
        path = jsons[-1]
    a = report_mod.load_assessment(path)
    if not a.authorized:
        print(f"Target not authorized; refusing to fetch: {a.scope_reason}")
        return 2
    a.findings = assess_mod.enrich_findings(a.findings)
    a.report_md, a.report_json = report_mod.write_report(a, path.parent)
    s = a.summary()
    print(f"Enriched {path.name}: {len(a.findings)} findings")
    print("Findings: " + ", ".join(
        f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
    ) + f", total={s['total']}")
    print(f"  Markdown: {a.report_md}")
    print(f"  JSON    : {a.report_json}")
    return 0


def _cmd_reparse(args) -> int:
    path = Path(args.path) if args.path else None
    if path is None or not path.exists():
        jsons = sorted(report_mod.REPORTS_DIR.glob("*.json"),
                       key=lambda p: p.stat().st_mtime)
        if not jsons:
            print("No assessment JSON files found in", report_mod.REPORTS_DIR)
            return 1
        path = jsons[-1]
    a = assess_mod.reparse_from_report(path)
    s = a.summary()
    print(f"Re-parsed {path.name} (target not re-scanned)")
    print("Findings: " + ", ".join(
        f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
    ) + f", total={s['total']}")
    print(f"  Markdown: {a.report_md}")
    print(f"  JSON    : {a.report_json}")
    return 0


def _cmd_matrix(args) -> int:
    if args.intrusive and not args.confirm_intrusive:
        print("Refused: SQLMap requires both --intrusive and --confirm-intrusive.")
        return 2
    if args.confirm_intrusive and not args.intrusive:
        print("Refused: --confirm-intrusive only applies with --intrusive.")
        return 2
    try:
        a = matrix_mod.run_matrix(
            args.target,
            operator=args.operator or "",
            wordlist=args.wordlist,
            rate=args.rate,
            cmd_timeout=args.timeout,
            include_intrusive=args.intrusive,
            confirm_intrusive=args.confirm_intrusive,
            reports_dir=Path(args.report_dir) if args.report_dir else None,
            job_source="cli",
        )
    except PermissionError as exc:
        print(f"Refused: {exc}")
        return 2
    if args.json:
        print(json.dumps(a.to_json(), indent=2))
        return 0 if a.authorized else 2
    print(f"\n=== Matrix scan: {a.target} ===")
    print(f"Scope    : {'AUTHORIZED' if a.authorized else 'DENIED'} — {a.scope_reason}")
    if not a.authorized:
        return 2
    s = a.summary()
    print("Findings : " + ", ".join(
        f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
    ) + f", total={s['total']}")
    if a.job_id:
        print(f"Job ID   : {a.job_id}")
    for c in a.commands:
        print(f"  - [{c.get('exit_code')}] {c.get('command')[:150]}")
    if a.report_md:
        print(f"Report   : {a.report_md}")
        print(f"JSON     : {a.report_json}")
    return 0


def _cmd_cve(args) -> int:
    if args.nmap_vuln and not args.confirm_intrusive:
        print("Refused: nmap vuln scripts require --confirm-intrusive.")
        return 2
    if args.confirm_intrusive and not args.nmap_vuln:
        print("Refused: --confirm-intrusive only applies with --nmap-vuln.")
        return 2
    try:
        a = cve_mod.run_cve_scan(
            args.target,
            severity=args.severity,
            latest=args.latest,
            rate=args.rate,
            concurrency=args.concurrency,
            nmap_vuln=args.nmap_vuln,
            confirm_intrusive=args.confirm_intrusive,
            run_latest=not args.no_latest,
            run_severity=not args.no_severity,
            operator=args.operator or "",
            cmd_timeout=args.timeout,
            reports_dir=Path(args.report_dir) if args.report_dir else None,
            job_source="cli",
        )
    except PermissionError as exc:
        print(f"Refused: {exc}")
        return 2

    if args.json:
        print(json.dumps(a.to_json(), indent=2))
        return 0 if a.authorized else 2
    if not a.authorized:
        return 2

    print(f"\n=== CVE scan: {a.target} ===")
    print(f"Scope    : {'AUTHORIZED' if a.authorized else 'DENIED'} — {a.scope_reason}")
    s = a.summary()
    print("Findings : " + ", ".join(
        f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
    ) + f", total={s['total']}")
    if a.job_id:
        print(f"Job ID   : {a.job_id}")
    for c in a.commands:
        print(f"  - [{c.get('exit_code')}] {c.get('command')[:170]}")
    if a.report_md:
        print(f"Report   : {a.report_md}")
        print(f"JSON     : {a.report_json}")
    return 0


def _cmd_intrusive(args) -> int:
    try:
        result = intrusive_mod.validate_werkzeug_console(
            args.url,
            confirm=args.confirm_authorized,
            execute=args.execute,
        )
    except intrusive_mod.IntrusiveNotAuthorized as exc:
        print(f"Refused: {exc}")
        return 2
    print(json.dumps(result, indent=2))
    if result.get("rce_confirmed"):
        print("\n[+] RCE CONFIRMED (harmless expression evaluated).")
    else:
        print("\n[-] RCE not confirmed; console exposure recorded.")
    return 0


def _cmd_serve(args) -> int:
    from .server import mcp
    mcp.run()
    return 0


def _cmd_infra(args) -> int:
    if args.intrusive and not args.confirm_intrusive:
        print("Refused: intrusive infra tooling requires --intrusive and "
              "--confirm-intrusive.")
        return 2
    if args.confirm_intrusive and not args.intrusive:
        print("Refused: --confirm-intrusive only applies with --intrusive.")
        return 2
    try:
        a = infra_mod.run_infra(
            args.target,
            operator=args.operator or "",
            rate=args.rate,
            cmd_timeout=args.timeout,
            include_intrusive=args.intrusive,
            confirm_intrusive=args.confirm_intrusive,
            reports_dir=Path(args.report_dir) if args.report_dir else None,
            job_source="cli",
        )
    except PermissionError as exc:
        print(f"Refused: {exc}")
        return 2

    if args.json:
        print(json.dumps(a.to_json(), indent=2))
        return 0 if a.authorized else 2
    print(f"\n=== Infra scan: {a.target} ===")
    print(f"Scope    : {'AUTHORIZED' if a.authorized else 'DENIED'} — {a.scope_reason}")
    if not a.authorized:
        return 2
    s = a.summary()
    print("Findings : " + ", ".join(
        f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
    ) + f", total={s['total']}")
    if a.job_id:
        print(f"Job ID   : {a.job_id}")
    for c in a.commands:
        print(f"  - [{c.get('exit_code')}] {c.get('command')[:150]}")
    if a.report_md:
        print(f"Report   : {a.report_md}")
        print(f"JSON     : {a.report_json}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kpm",
        description="Kali Pentest MCP — scope-enforced bug-bounty assessments.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scope", help="Show the active scope and rules.")
    sp.set_defaults(func=_cmd_scope)

    sp = sub.add_parser("scope-check", help="Check whether a target is authorized.")
    sp.add_argument("target")
    sp.set_defaults(func=_cmd_scope_check)

    sp = sub.add_parser("assess", help="Run a scoped assessment.")
    sp.add_argument("target")
    sp.add_argument("--profile", default="web", choices=["web", "network", "full"])
    sp.add_argument("--operator", default="")
    sp.add_argument("--wordlist", default=None)
    sp.add_argument("--deep", action="store_true",
                    help="Use the full seclists wordlist and enable the nuclei "
                         "web sweep (slower).")
    sp.add_argument("--nuclei", action="store_true",
                    help="Run a nuclei sweep (medium,high,critical) in the web "
                         "profile; also implied by --deep.")
    sp.add_argument("--no-cve-intel", action="store_true",
                    help="Skip CVSS/EPSS enrichment (no calls to FIRST.org/NVD).")
    sp.add_argument("--dry-run", action="store_true",
                    help="Show the plan without executing anything.")
    sp.add_argument("--all-ports", action="store_true",
                    help="Scan every http port nmap finds, not just 80/443 "
                         "(slower, mostly needed behind CDNs).")
    sp.add_argument("--ignore-block", action="store_true",
                    help="Proceed even if the edge returns a WAF block page "
                         "(unreliable; only when the program permits it).")
    sp.add_argument("--nikto-maxtime", type=int, default=None,
                    metavar="SECONDS",
                    help="Max seconds nikto spends per host (default 120; "
                         "lower it to 60 for a faster, shallower scan).")
    sp.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    sp.add_argument("--no-report", action="store_true",
                    help="Do not write report files.")
    sp.add_argument("--report-dir", default=None)
    sp.set_defaults(func=_cmd_assess)

    sp = sub.add_parser("report", help="Regenerate a report from stored JSON.")
    sp.add_argument("--path", default=None, help="Path to an assessment JSON.")
    sp.set_defaults(func=_cmd_report)

    sp = sub.add_parser(
        "reparse",
        help="Re-derive findings from stored artifacts (no re-scan).",
    )
    sp.add_argument("--path", default=None, help="Path to an assessment JSON.")
    sp.set_defaults(func=_cmd_reparse)

    sp = sub.add_parser(
        "enrich",
        help="Fetch body evidence for exposed sensitive files in a report.",
    )
    sp.add_argument("--path", default=None, help="Path to an assessment JSON.")
    sp.set_defaults(func=_cmd_enrich)

    sp = sub.add_parser("serve", help="Run the MCP server (stdio).")
    sp.set_defaults(func=_cmd_serve)

    sp = sub.add_parser(
        "cve",
        help="CVE scan via nuclei templates + nmap vuln scripts "
             "(scope-enforced, rate-limited).",
    )
    sp.add_argument("target")
    sp.add_argument("--severity", default="high,critical",
                    help="nuclei severities to sweep (default high,critical).")
    sp.add_argument("--latest", type=int, default=10,
                    help="Also run the N newest CVE templates (default 10).")
    sp.add_argument("--rate", type=int, default=None,
                    help="requested nuclei requests/second; always clamped to scope rules.")
    sp.add_argument("--concurrency", type=int, default=None,
                    help="requested nuclei concurrency; always clamped to scope rules.")
    sp.add_argument("--timeout", type=int, default=1500,
                    help="Max seconds per nuclei/nmap phase (default 1500).")
    sp.add_argument("--operator", default="")
    sp.add_argument("--nmap-vuln", action="store_true",
                    help="Request Nmap vuln scripts (intrusive; requires scope authorization and confirmation).")
    sp.add_argument("--confirm-intrusive", action="store_true",
                    help="Confirm Nmap vuln scripts are explicitly authorized by the program.")
    sp.add_argument("--no-nmap", dest="nmap_vuln", action="store_false",
                    help="Skip Nmap NSE vuln scripts (default).")
    sp.add_argument("--no-latest", action="store_true",
                    help="Skip the newest-CVE-template run.")
    sp.add_argument("--no-severity", action="store_true",
                    help="Skip the severity-wide sweep.")
    sp.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    sp.add_argument("--report-dir", default=None)
    sp.set_defaults(nmap_vuln=False)
    sp.set_defaults(func=_cmd_cve)

    sp = sub.add_parser(
        "matrix",
        help="Run ALL applicable tools (nmap, nikto, gobuster, ffuf, dirb, "
             "whatweb, wapiti, wpscan, sqlmap, nuclei, searchsploit, dnsrecon).",
    )
    sp.add_argument("target")
    sp.add_argument("--operator", default="")
    sp.add_argument("--wordlist", default=None)
    sp.add_argument("--rate", type=int, default=20)
    sp.add_argument("--timeout", type=int, default=900)
    sp.add_argument("--intrusive", action="store_true",
                    help="Request the intrusive SQLMap phase (disabled by default).")
    sp.add_argument("--confirm-intrusive", action="store_true",
                    help="Explicitly confirm SQLMap is authorized by the program.")
    sp.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    sp.add_argument("--report-dir", default=None)
    sp.set_defaults(func=_cmd_matrix)

    sp = sub.add_parser(
        "infra",
        help="Infrastructure scan (firewalls, Windows/AD, switches, Linux) — "
             "service-driven and scope-enforced.",
    )
    sp.add_argument("target")
    sp.add_argument("--operator", default="")
    sp.add_argument("--rate", type=int, default=20,
                    help="requests/second ceiling (clamped to scope rules).")
    sp.add_argument("--timeout", type=int, default=900,
                    help="Max seconds per tool (default 900).")
    sp.add_argument("--intrusive", action="store_true",
                    help="Enable gated intrusive tools (nmap vuln scripts, "
                         "credential attacks).")
    sp.add_argument("--confirm-intrusive", action="store_true",
                    help="Confirm intrusive testing is authorized by the program.")
    sp.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    sp.add_argument("--report-dir", default=None)
    sp.set_defaults(func=_cmd_infra)

    sp = sub.add_parser(
        "intrusive",
        help="Opt-in, non-destructive intrusive validation "
             "(requires --confirm-authorized and allow_intrusive: true).",
    )
    sp.add_argument("--url", required=True,
                    help="Target URL, e.g. https://host/console")
    sp.add_argument("--execute", default="40+2",
                    help="Harmless Python expression to evaluate as proof.")
    sp.add_argument("--confirm-authorized", action="store_true",
                    help="Acknowledge you are explicitly authorized to test.")
    sp.set_defaults(func=_cmd_intrusive)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
