"""WAF detection and origin-exposure checks.

For an *authorized* target this reports two things:

* whether a WAF sits in front of it (and which vendor), and
* whether the target's origin IP is directly reachable, which means the
  WAF can potentially be bypassed by talking to the origin instead.

Safety
------
The target is scope-checked with :mod:`src.scope` (deny-by-default). Probing
an origin IP is a request to a *different host* than the domain, so the origin
probe only runs when that IP is itself authorized by the active scope.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import jobs
from . import runner
from . import scope

log = logging.getLogger("kpm.waf")

HTTP_TIMEOUT = 15
MAX_BODY = 65536

# Header / cookie substrings that identify common WAFs and CDNs.
WAF_SIGNATURES: dict[str, str] = {
    "incap_ses": "Imperva Incapsula",
    "visid_incap": "Imperva Incapsula",
    "x-iinfo": "Imperva Incapsula",
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "__cfduid": "Cloudflare",
    "cf-request-id": "Cloudflare",
    "x-akamai": "Akamai",
    "akamai-grn": "Akamai",
    "x-amz-cf-id": "AWS CloudFront",
    "awselb": "AWS Elastic Load Balancer",
    "awsalb": "AWS Application Load Balancer",
    "x-amzn-requestid": "AWS",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "barra_counter_session": "Barracuda",
    "bigipserver": "F5 BIG-IP",
    "mod_security": "ModSecurity",
    "modsecurity": "ModSecurity",
    "x-waf": "Generic WAF",
    "x-protected-by": "Generic WAF",
    "ddos-guard": "DDoS-Guard",
    "server: cloudflare": "Cloudflare",
    "server: sucuri": "Sucuri",
    "server: ddos-guard": "DDoS-Guard",
}


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    present: bool = False
    vendors: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    status: int | None = None
    reachable: bool = True
    error: str | None = None


@dataclass
class OriginProbe:
    ip: str
    in_scope: bool = False
    tested: bool = False
    reachable: bool = False
    status: int | None = None
    vendor_headers: list[str] = field(default_factory=list)
    bypass_likely: bool = False
    error: str | None = None


@dataclass
class WafReport:
    target: str
    authorized: bool
    scope_reason: str
    detection: Detection = field(default_factory=Detection)
    origins: list[OriginProbe] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    job_id: str = ""

    def summary(self) -> dict:
        return {
            "target": self.target,
            "authorized": self.authorized,
            "waf_present": self.detection.present,
            "waf_vendors": list(self.detection.vendors),
            "origins": [o.ip for o in self.origins],
            "bypass_likely": [o.ip for o in self.origins if o.bypass_likely],
            "flags": list(self.flags),
        }

    def to_text(self) -> str:
        if not self.authorized:
            return f"Refused: {self.target} — {self.scope_reason}"

        d = self.detection
        lines = [f"# WAF Assessment: {self.target}", ""]

        if d.present:
            lines.append(f"## WAF detected: {', '.join(d.vendors)}")
            for item in d.evidence:
                lines.append(f"- {item}")
        elif not d.reachable:
            lines.append("## WAF status unknown")
            lines.append(f"- target not reachable ({d.error})")
        else:
            lines.append("## No WAF detected")

        lines.append("")
        lines.append("## Origin IP exposure")
        if not self.origins:
            lines.append("- Could not resolve the target to an IP address.")
        for o in self.origins:
            lines.append(f"- Resolved IP: {o.ip}")
            if not o.in_scope:
                lines.append("  - skipped: IP not in scope, origin probe not run")
            elif not o.tested:
                lines.append("  - origin probe not run")
            elif not o.reachable:
                lines.append(f"  - origin not directly reachable ({o.error})")
            else:
                lines.append(f"  - origin reachable, HTTP status {o.status}")
                if o.vendor_headers:
                    lines.append(
                        "  - WAF still present on origin response: "
                        + ", ".join(o.vendor_headers)
                    )
        lines.append("")
        lines.append("## Flags")
        lines.extend(self.flags or ["- No exposure flags raised."])
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _hostname(target: str) -> str:
    return scope.normalize_host(target)


def _base_url(target: str) -> str:
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    parsed = urllib.parse.urlparse(t)
    if not parsed.scheme:
        parsed = parsed._replace(scheme="http")
    if not parsed.netloc:
        return f"{parsed.scheme}://{parsed.path}"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_request(url: str, *, host_header: str | None = None,
                  user_agent: str = "KaliPentestMCP/1.0") -> tuple[int, str, str]:
    """GET *url*, returning ``(status, header_blob, body_snippet)``."""
    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    if host_header:
        headers["Host"] = host_header
    request = urllib.request.Request(url, headers=headers)
    context = _ssl_context() if url.lower().startswith("https") else None
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT,
                                context=context) as response:
        status = response.status
        blob = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        body = response.read(MAX_BODY).decode("utf-8", "replace")
    return status, blob, body


def _match_vendors(header_blob: str) -> list[str]:
    lowered = header_blob.lower()
    found: list[str] = []
    for signature, vendor in WAF_SIGNATURES.items():
        if signature in lowered and vendor not in found:
            found.append(vendor)
    return found


def _parse_wafw00f(output: str) -> list[str]:
    """Extract detected WAF names from wafw00f JSON output."""
    names: list[str] = []
    try:
        data = json.loads(output)
    except (ValueError, TypeError):
        return names
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return names
    for entry in data:
        if isinstance(entry, dict) and entry.get("detected"):
            name = entry.get("firewall") or entry.get("manufacturer")
            if name and name not in names:
                names.append(str(name))
    return names


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> list[str]:
    """Resolve a hostname to a list of unique IP addresses."""
    ips: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return ips
    for info in infos:
        address = info[4][0]
        if address not in ips:
            ips.append(address)
    return ips


def detect_waf(target: str, *, user_agent: str = "KaliPentestMCP/1.0") -> Detection:
    """Detect whether a WAF protects *target*."""
    result = Detection()

    # Optional wafw00f fingerprinting (skipped gracefully if not installed).
    try:
        wafw00f = runner.run(["wafw00f", target, "-f", "json"], timeout=60)
        for name in _parse_wafw00f(wafw00f.stdout):
            if name not in result.vendors:
                result.vendors.append(name)
                result.evidence.append(f"wafw00f: {name}")
    except Exception as exc:  # noqa: BLE001
        log.debug("wafw00f unavailable: %s", exc)

    # Header / cookie heuristic against the live target.
    try:
        status, blob, _ = _http_request(_base_url(target), user_agent=user_agent)
        result.status = status
        for vendor in _match_vendors(blob):
            if vendor not in result.vendors:
                result.vendors.append(vendor)
                result.evidence.append(f"header/cookie: {vendor}")
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
        result.reachable = False
        result.error = str(exc)

    result.present = bool(result.vendors)
    return result


def probe_origin(host: str, ip: str, *, user_agent: str = "KaliPentestMCP/1.0",
                 schemes: tuple[str, ...] = ("http", "https")) -> OriginProbe:
    """Check whether an origin *ip* serves *host* directly."""
    probe = OriginProbe(ip=ip, in_scope=True, tested=True)
    for scheme in schemes:
        try:
            status, blob, _ = _http_request(
                f"{scheme}://{ip}/", host_header=host, user_agent=user_agent,
            )
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
            probe.error = str(exc)
            continue
        probe.reachable = True
        probe.status = status
        probe.vendor_headers = _match_vendors(blob)
        if not probe.vendor_headers:
            probe.bypass_likely = True
        return probe
    return probe


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_waf_check(target: str, *, job_source: str = "mcp") -> WafReport:
    """Scope-checked WAF + origin-exposure assessment."""
    ok, reason = scope.check(target)
    report = WafReport(target=target, authorized=ok, scope_reason=reason)
    if not ok:
        return report

    rules = scope.get_scope().rules
    user_agent = str(rules.get("user_agent") or "KaliPentestMCP/1.0")
    allowed_ports = [int(p) for p in (rules.get("allowed_ports") or [])]
    allowed_schemes = [str(s).lower() for s in (rules.get("allowed_schemes") or [])]

    schemes = ("http", "https")
    if allowed_schemes:
        schemes = tuple(s for s in schemes if s in allowed_schemes) or schemes
    if allowed_ports and not ({80, 443} & set(allowed_ports)):
        schemes = ()

    host = _hostname(target)

    jid = jobs.create_job("waf", target, source=job_source, agent="WAF Agent")
    jobs.record_event(jid, {"type": "scan_start", "target": target, "profile": "waf"})
    jobs.record_event(jid, {"type": "plan", "steps": [
        {"key": "waf_check", "label": "WAF detection", "agent": "WAF Agent"},
    ]})
    jobs.record_event(jid, {"type": "step_start", "key": "waf_check",
                            "label": "WAF detection", "agent": "WAF Agent"})

    report.detection = detect_waf(target, user_agent=user_agent)

    for ip in resolve_host(host):
        origin = OriginProbe(ip=ip)
        origin.in_scope = scope.check(ip)[0]
        if origin.in_scope and schemes:
            origin = probe_origin(host, ip, user_agent=user_agent, schemes=schemes)
        report.origins.append(origin)

    # Flags ------------------------------------------------------------------
    if not report.detection.present:
        report.flags.append(
            "[!] NO WAF IN PLACE - the target appears to have no web "
            "application firewall in front of it."
        )
    for origin in report.origins:
        if origin.bypass_likely:
            report.flags.append(
                f"[!] ORIGIN IP REACHABLE ({origin.ip}) - the WAF can likely "
                "be bypassed by sending requests straight to the origin."
            )

    jobs.record_event(jid, {"type": "step_end", "key": "waf_check",
                            "label": "WAF detection", "agent": "WAF Agent",
                            "status": "done", "exit_code": 0,
                            "duration_ms": 0, "findings": len(report.flags)})
    jobs.record_event(jid, {"type": "scan_done", "status": "done",
                            "findings": {"critical": 0, "high": 0, "medium": 0,
                                         "low": 0, "info": len(report.flags),
                                         "total": len(report.flags)}})
    report.job_id = jid
    return report
