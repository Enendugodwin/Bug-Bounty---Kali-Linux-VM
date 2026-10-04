"""Normalize raw scanner output into structured findings.

Each parser is defensive: it never raises on unexpected input, it simply
returns whatever findings it could extract. Severity is heuristic — the
report always carries the raw evidence so a human can review it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

SEVERITIES = ["critical", "high", "medium", "low", "info"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    target: str
    tool: str
    endpoint: str = ""
    port: int | None = None
    confidence: str = "medium"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    validation_status: str = "unverified"

    def to_dict(self) -> dict:
        return asdict(self)


def _fid(title: str, endpoint: str, target: str) -> str:
    raw = f"{title}|{endpoint}|{target}".encode("utf-8", "replace")
    return hashlib.sha1(raw).hexdigest()[:10]


def _mk(title, severity, target, tool, **kw) -> Finding:
    endpoint = kw.pop("endpoint", "")
    fid = _fid(title, endpoint, target)
    return Finding(id=fid, title=title, severity=severity, target=target,
                   tool=tool, endpoint=endpoint, **kw)


def _clip(text: str, limit: int = 1200) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


# ---------------------------------------------------------------------------
# Severity heuristics
# ---------------------------------------------------------------------------

_NIKTO_HIGH = [
    ("remote code", "critical"), ("command execution", "critical"),
    ("rce", "critical"), ("sql", "high"), ("inject", "high"),
    ("cross site", "high"), ("cross-site", "high"), ("xss", "high"),
    ("file inclusion", "high"), ("directory traversal", "high"),
    ("path traversal", "high"), ("lfi", "high"), ("rfi", "high"),
    ("default password", "high"), ("default credential", "high"),
    ("default login", "high"), ("default account", "high"),
    ("default installation", "high"), ("commonspam", "high"),
]
_NIKTO_MED = [
    ("directory indexing", "medium"), ("index of", "medium"),
    ("osvdb", "medium"), ("outdated", "medium"), ("vulnerable", "medium"),
    ("cve-", "medium"), ("phpinfo", "medium"), ("backup", "medium"),
    ("disclosure", "medium"), ("cookie", "low"), ("httponly", "low"),
    ("secure flag", "low"),
]
_NIKTO_LOW = [
    ("header is not present", "low"), ("not set", "low"),
    ("missing", "low"), ("x-frame-options", "low"),
    ("x-content-type", "low"), ("content-security", "low"),
    ("anti-clickjacking", "low"), ("hsts", "low"),
    ("strict-transport", "low"), ("uncommon header", "low"),
    ("access-control-allow-origin", "low"),
]

_RISKY_SERVICES = {
    "ftp": "medium", "ftp-data": "medium", "telnet": "high", "rlogin": "high",
    "rsh": "high", "vnc": "high", "smb": "medium", "microsoft-ds": "medium",
    "netbios-ssn": "medium", "netbios-ns": "low", "ms-wbt-server": "medium",
    "rdp": "medium", "ldap": "medium", "ldaps": "low", "mysql": "medium",
    "postgresql": "medium", "ms-sql-s": "medium", "redis": "high",
    "mongodb": "high", "elasticsearch": "high", "memcached": "high",
    "smtp": "low", "pop3": "low", "imap": "low", "snmp": "medium",
}
_WEB_SERVICES = {"http", "https", "http-alt", "http-proxy", "ssl/http",
                 "ssl/https", "http?nginx", "http?apache"}

_SENSITIVE_PATHS = [
    (".git", "high"), (".env", "high"), (".svn", "high"), (".hg", "high"),
    ("backup", "medium"), (".bak", "medium"), (".old", "medium"),
    (".sql", "high"), ("dump", "high"), ("config", "medium"),
    ("phpinfo", "medium"), ("server-status", "medium"), ("actuator", "medium"),
    ("swagger", "medium"), ("api-docs", "medium"), ("admin", "medium"),
    ("phpmyadmin", "high"), ("wp-admin", "low"), ("console", "medium"),
    ("manager", "medium"), ("debug", "medium"), ("test", "low"),
    (".htaccess", "medium"), ("web.config", "medium"),
]


def _has(text: str, needle: str) -> bool:
    """Whole-token match so e.g. 'rce' does not match 'force'."""
    return re.search(
        r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", text
    ) is not None


def _sev_from_text(text: str) -> str:
    low = text.lower()
    # "Uncommon header" notes are fingerprints, not vulnerabilities.
    if "uncommon header" in low:
        return "info"
    for needle, sev in _NIKTO_HIGH:
        if _has(low, needle):
            return sev
    for needle, sev in _NIKTO_MED:
        if _has(low, needle):
            return sev
    for needle, sev in _NIKTO_LOW:
        if _has(low, needle):
            return sev
    return "info"


_PATH_RE = re.compile(r"(/(?:[\w.\-]+/)*[\w.\-]*)")


def _endpoint_in(text: str) -> str:
    m = _PATH_RE.search(text)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

_NMAP_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|open\|filtered|filtered)\s+(\S+)\s*(.*)$",
    re.IGNORECASE,
)


def parse_nmap(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in stdout.splitlines():
        m = _NMAP_PORT_RE.match(line.strip())
        if not m:
            continue
        port, proto, state, service, version = m.groups()
        if "open" not in state:
            continue
        svc = service.lower().rstrip("?")
        is_web_listener = (
            int(port) in {80, 443, 8000, 8080, 8443, 8888}
            or svc in _WEB_SERVICES
            or svc.startswith(("http", "ssl/http", "ssl/https"))
        )
        # A public HTTP(S) listener is expected for a website, not itself a
        # vulnerability; only report it as informational attack-surface data.
        sev = "info" if is_web_listener else _RISKY_SERVICES.get(svc, "low")
        banner = " ".join(x for x in (service, version.strip()) if x)
        title = f"Open port {port}/{proto} — {service}"
        findings.append(_mk(
            title, sev, target, "nmap",
            port=int(port), endpoint=f"{target}:{port}",
            confidence="high" if svc in _RISKY_SERVICES else "medium",
            description=(f"Port {port}/{proto} is open running '{banner}'. "
                         + ("This service can widen the attack surface."
                            if sev not in ("info",) else
                            "Standard web service.")),
            evidence=f"{port}/{proto} {state} {banner}".strip(),
            remediation=("Restrict access to this port with a firewall / "
                         "network ACL if it is not required publicly."
                         if sev not in ("info",) else
                         "Confirm the service is intended to be public."),
            references=["https://www.cisa.gov/secure-our-world"],
        ))
    return findings


def parse_nikto(stdout: str, target: str, base_url: str = "") -> list[Finding]:
    findings: list[Finding] = []
    skip_markers = (
        "target ip:", "target hostname:", "target port:", "start time:",
        "end time:", "host(s) tested", "server leaks inodes",
        "no cgi directories", "cgi tests skipped", "item(s) reported",
        "items checked", "scan terminated", "ssl info:", "platform:",
        "multiple ips found", "server:", "host(s) tested",
    )

    def _is_noise(body: str) -> bool:
        low = body.lower()
        if any(marker in low for marker in skip_markers):
            return True
        if low.startswith("status:"):
            return True
        if body.upper().startswith("ERROR"):
            return True
        return False

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line.startswith("+"):
            continue
        body = line[1:].strip()
        if not body or _is_noise(body):
            continue
        sev = _sev_from_text(body)
        endpoint = _endpoint_in(body)
        title = body if len(body) <= 100 else body[:97] + "..."
        url = urljoin(base_url, endpoint) if (base_url and endpoint) else base_url
        findings.append(_mk(
            title, sev, target, "nikto",
            endpoint=url or endpoint,
            confidence="medium" if sev != "info" else "low",
            description="Reported by Nikto during a web configuration scan.",
            evidence=body,
            remediation=("Review the affected endpoint and apply the "
                         "vendor/hardening guidance for this issue."),
            references=["https://cve.mitre.org/", "https://owasp.org/"],
        ))
    return findings


_GOBUSTER_RE = re.compile(
    r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
    re.IGNORECASE,
)


def parse_gobuster(stdout: str, target: str, base_url: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _GOBUSTER_RE.search(line)
        if not m:
            continue
        path, status, size = m.group(1), int(m.group(2)), m.group(3)
        low = path.lower()
        if 300 <= status < 400:
            # Redirects are routing/vanity URLs, not discovered resources.
            sev = "info"
        elif status in (401, 403):
            # Auth challenges/forbidden responses do not prove exposure.
            sev = "info"
        else:
            sev = "info"
            if status == 200:
                for needle, s in _SENSITIVE_PATHS:
                    if needle in low:
                        sev = s
                        break
            if status == 200 and sev == "info":
                sev = "low"
        full = urljoin(base_url, path) if base_url else path
        findings.append(_mk(
            f"Discovered path: {path}", sev, target, "gobuster",
            endpoint=full,
            confidence="high" if status == 200 else "low",
            description=(f"Directory/file discovery found '{path}' "
                         f"(HTTP {status})."),
            evidence=line,
            remediation=("Confirm whether this resource should be publicly "
                         "reachable; restrict or remove if not."),
            references=["https://owasp.org/www-community/attacks/Forced_browsing"],
        ))
    return findings


def parse_ffuf_json(text: str, target: str, base_url: str = "") -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return findings
    for item in data.get("results", []) or []:
        url = item.get("url", "")
        status = item.get("status")
        length = item.get("length")
        low = url.lower()
        sev = "info"
        if status == 200:
            for needle, s in _SENSITIVE_PATHS:
                if needle in low:
                    sev = s
                    break
            if sev == "info" and status == 200:
                sev = "low"
        findings.append(_mk(
            f"Discovered path: {url}", sev, target, "ffuf",
            endpoint=url, confidence="high" if status == 200 else "low",
            description=f"ffuf discovered a resource (HTTP {status}).",
            evidence=f"{url} (Status: {status}, Length: {length})",
            remediation="Review exposed resource and restrict if unintended.",
            references=["https://owasp.org/www-community/attacks/Forced_browsing"],
        ))
    return findings


_PARSERS = {
    "nmap": lambda out, t, u="": parse_nmap(out, t),
    "nikto": parse_nikto,
    "gobuster": parse_gobuster,
    "ffuf": parse_ffuf_json,
}


def parse_output(tool: str, stdout: str, target: str,
                 base_url: str = "") -> list[Finding]:
    """Dispatch to the parser for *tool*; tolerate unknown tools."""
    key = (tool or "").strip().lower()
    parser = _PARSERS.get(key)
    if parser is None:
        return []
    try:
        return parser(stdout, target, base_url)
    except Exception:  # noqa: BLE001 - never let parsing break a scan
        return []


def _endpoint_key(endpoint: str) -> str:
    """Normalize endpoint scheme/default port while preserving meaningful paths."""
    e = (endpoint or "").strip()
    if not e:
        return ""
    parsed = urlsplit(e if "://" in e else "//" + e)
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port in (80, 443):
        port = None
    if not host:
        return re.sub(r"^https?://", "", e.lower()).rstrip("/")
    authority = host + (f":{port}" if port else "")
    path = re.sub(r"/{2,}", "/", parsed.path or "").rstrip("/")
    query = parsed.query
    return authority + path + (f"?{query}" if query else "")


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.I)
_SENSITIVE_FILE_RE = re.compile(
    r"(?:^|/)(?:\.env(?:\.[^/]*)?|\.git(?:/.*)?|\.svn(?:/.*)?|"
    r"\.hg(?:/.*)?|[^/]+\.(?:sql|bak|backup|old|dump|zip|tgz))(?:$|\?)",
    re.I,
)


def _canonical_key(f: Finding) -> tuple[str, str, str]:
    endpoint = _endpoint_key(f.endpoint)
    text = f"{f.title} {f.description} {' '.join(f.references)}"
    cve = _CVE_RE.search(text)
    if cve:
        return ("cve", cve.group(0).lower(), endpoint)

    parsed = urlsplit(f.endpoint if "://" in f.endpoint else "//" + f.endpoint)
    path = parsed.path or f.endpoint
    if _SENSITIVE_FILE_RE.search(path):
        return ("sensitive-file", endpoint, "")

    title = f.title.strip().lower()
    discovery_tools = {"gobuster", "dirb", "ffuf"}
    if f.tool.lower() in discovery_tools or "discovered path" in title:
        return ("web-resource", endpoint, "")

    # Normalize scanner prefixes / plugin numbers, retaining the issue wording.
    title = re.sub(r"^\[[0-9]+\]\s*", "", title)
    title = re.sub(r"^(?:nikto|wapiti|nuclei|wpscan|whatweb):\s*", "", title)
    return (title, endpoint, "")


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge cross-tool duplicates, retaining worst severity and all sources."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = _canonical_key(f)
        cur = best.get(key)
        if cur is None:
            if not f.sources:
                f.sources = [f.tool]
            best[key] = f
            continue
        sources = sorted(set((cur.sources or [cur.tool]) + (f.sources or [f.tool])))
        severity = min((cur.severity, f.severity), key=lambda s: _RANK.get(s, 99))
        confidence_rank = {"low": 0, "medium": 1, "high": 2}
        validation_rank = {"unverified": 0, "needs_manual_validation": 1,
                           "scanner_match": 2, "confirmed": 3}
        def quality(item: Finding) -> tuple[int, int, int, int, int]:
            generic = item.title.lower().startswith((
                "discovered path", "public exploit match", "possible exploit-db"
            ))
            return (
                validation_rank.get(item.validation_status, 0),
                confidence_rank.get(item.confidence, 0),
                0 if generic else 1,
                len(item.title),
                len(item.description),
            )

        if quality(f) > quality(cur):
            winner, other = f, cur
        else:
            winner, other = cur, f
        winner.severity = severity
        winner.sources = sources
        winner.references = list(dict.fromkeys(cur.references + f.references))
        winner.evidence = "\n\n--- Additional tool evidence ---\n\n".join(
            dict.fromkeys(x for x in (cur.evidence, f.evidence) if x)
        )[:4000]
        winner.validation_status = max(
            (cur.validation_status, f.validation_status),
            key=lambda s: validation_rank.get(s, 0),
        )
        if len(other.description) > len(winner.description):
            winner.description = other.description
        best[key] = winner
    return sorted(best.values(), key=lambda x: (_RANK[x.severity], x.title))


# ---------------------------------------------------------------------------
# WAF block-page artifact quarantine
# ---------------------------------------------------------------------------
# When an edge/WAF answers a scanner probe with a block or challenge page, the
# scanner's parser can mistake that page for a finding (e.g. nikto reporting an
# "uncommon header x-iinfo", or an RFC-1918 IP from the block page). These
# markers let us quarantine such artifacts instead of presenting them as
# vulnerabilities. Real findings rarely quote these strings in their evidence.

_WAF_ARTIFACT_MARKERS = (
    "x-iinfo", "incap_ses", "visid_incap", "incapsula",
    "_incapsula_resource", "incapsula incident id",
    "request unsuccessful", "cf-mitigated", "attention required",
    "error 1010", "error 1020", "just a moment",
    "checking your browser", "sucuri website firewall", "x-sucuri-id",
    "ddos-guard", "bigipserver", "the requested url was rejected",
)


def is_waf_block_artifact(f: Finding) -> bool:
    """True when a finding's own text quotes a WAF block/challenge page."""
    blob = f"{f.title}\n{f.description}\n{f.evidence}".lower()
    return any(marker in blob for marker in _WAF_ARTIFACT_MARKERS)


def quarantine_waf_artifacts(
    findings: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into ``(kept, quarantined)`` by block-page markers."""
    kept: list[Finding] = []
    quarantined: list[Finding] = []
    for f in findings:
        (quarantined if is_waf_block_artifact(f) else kept).append(f)
    return kept, quarantined


def summarize(findings: list[Finding]) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts
