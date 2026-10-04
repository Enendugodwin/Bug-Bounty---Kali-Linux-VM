"""OWASP ZAP integration (scope-gated).

Talks to a running ZAP instance over its REST API (default
``http://127.0.0.1:8090``) and exposes three operations:

* ``run_spider``      — traditional spider restricted to a ZAP *context*
                        whose include regex only matches the target host.
* ``run_alerts``      — read alerts ZAP has recorded for a base URL.
* ``run_active_scan`` — active scan. **Triple-gated**: explicit
                        ``confirm_active`` flag, ``allow_active_scan: true``
                        in ``scope.yaml`` rules, and the target in scope.
                        Active scanning is aggressive; only use it where the
                        program explicitly permits it.

Every entry point calls :func:`src.scope.check` first (deny-by-default). ZAP
is optional: if it is not running these functions return a clear "unreachable"
result instead of raising.

Configuration (environment):
    ZAP_API_URL   default http://127.0.0.1:8090
    ZAP_API_KEY   optional; sent as the ``apikey`` parameter
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import jobs
from . import scope

log = logging.getLogger("kpm.zap")

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://127.0.0.1:8090").rstrip("/")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

HTTP_TIMEOUT = 30
SPIDER_POLL = 2.0
ACTIVE_POLL = 3.0

RISK_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


class ZapError(Exception):
    """Raised when the ZAP API returns an error or is unreachable."""


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    name: str
    risk: str
    confidence: str = ""
    url: str = ""
    param: str = ""
    evidence: str = ""
    solution: str = ""
    cweid: str = ""

    @property
    def severity(self) -> str:
        return RISK_SEVERITY.get((self.risk or "").lower(), "info")


@dataclass
class ZapReport:
    target: str
    action: str
    authorized: bool
    scope_reason: str
    available: bool = True
    version: str = ""
    scan_id: str = ""
    progress: int = 0
    urls_found: int = 0
    alerts: list[Alert] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    error: str | None = None
    job_id: str = ""

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for a in self.alerts:
            counts[a.severity] = counts.get(a.severity, 0) + 1
        return {
            "target": self.target,
            "action": self.action,
            "urls_found": self.urls_found,
            "alerts_total": len(self.alerts),
            "by_severity": counts,
            "flags": list(self.flags),
        }

    def to_text(self) -> str:
        if not self.authorized:
            return f"Refused: {self.target} — {self.scope_reason}"
        if not self.available:
            return (f"ZAP unavailable at {ZAP_API_URL} — {self.error}\n"
                    "Start it with: zap.sh -daemon -host 127.0.0.1 -port 8090")
        if self.error:
            return f"ZAP {self.action} failed for {self.target}: {self.error}"

        lines = [f"# ZAP {self.action}: {self.target}", ""]
        lines.append(f"ZAP version: {self.version}")
        if self.scan_id:
            lines.append(f"Scan ID: {self.scan_id} (progress {self.progress}%)")
        if self.urls_found:
            lines.append(f"URLs found: {self.urls_found}")
        counts = self.summary()["by_severity"]
        lines.append("Alerts: " + (", ".join(
            f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
        lines.append("")
        if self.alerts:
            lines.append("## Alerts")
            for a in self.alerts[:50]:
                lines.append(
                    f"- [{a.severity.upper()}] {a.name} — {a.url}"
                    + (f" (param: {a.param})" if a.param else "")
                )
        if self.flags:
            lines.append("")
            lines.append("## Flags")
            lines.extend(self.flags)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _api(component: str, view: str, name: str, params: dict | None = None) -> dict:
    """Call a ZAP JSON API endpoint and return the parsed body."""
    query = dict(params or {})
    if ZAP_API_KEY:
        query["apikey"] = ZAP_API_KEY
    url = (
        f"{ZAP_API_URL}/JSON/{component}/{view}/{name}/"
        f"?{urllib.parse.urlencode(query)}"
    )
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        raise ZapError(
            f"ZAP API {exc.code} on {component}/{name}: {detail or exc.reason}"
        ) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ZapError(f"ZAP unreachable at {ZAP_API_URL}: {exc}") from exc

    try:
        data = json.loads(body)
    except ValueError as exc:
        raise ZapError(f"unexpected ZAP response: {body[:200]}") from exc

    if isinstance(data, dict) and data.get("code") and data.get("message"):
        raise ZapError(f"ZAP error: {data.get('message')}")
    return data if isinstance(data, dict) else {}


def _version() -> str:
    data = _api("core", "view", "version")
    return str(data.get("version", ""))


def _base_url(target: str) -> str:
    t = (target or "").strip()
    if "://" not in t:
        t = "https://" + t
    parsed = urllib.parse.urlparse(t)
    if not parsed.netloc:
        raise ZapError(f"cannot parse target: {target}")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _ensure_context(host: str) -> str:
    """Create a ZAP context whose include regex only matches *host*."""
    name = f"kpm-{host}"
    try:
        _api("context", "action", "newContext", {"contextName": name})
    except ZapError:
        pass  # context may already exist
    _api("context", "action", "includeInContext", {
        "contextName": name,
        "regex": f"^https?://{re.escape(host)}(:\\d+)?(/.*)?$",
    })
    return name


def _parse_alerts(payload: dict) -> list[Alert]:
    out: list[Alert] = []
    for raw in payload.get("alerts", []) or []:
        if not isinstance(raw, dict):
            continue
        out.append(Alert(
            name=str(raw.get("alert", "")),
            risk=str(raw.get("risk", "")),
            confidence=str(raw.get("confidence", "")),
            url=str(raw.get("url", "")),
            param=str(raw.get("param", "")),
            evidence=str(raw.get("evidence", "")),
            solution=str(raw.get("solution", "")),
            cweid=str(raw.get("cweid", "")),
        ))
    return out


def fetch_alerts(target: str, *, count: int = 200) -> list[Alert]:
    base = _base_url(target)
    data = _api("alert", "view", "alerts", {"baseurl": base, "start": 0,
                                            "count": count})
    return _parse_alerts(data)


def _apply_politeness(rps: int) -> None:
    """Best-effort throttling so ZAP stays within the scope rate limit.

    ZAP's traditional spider has no requests-per-second option, so we use a
    single thread (serial requests) with a bounded depth and duration.
    """
    _ = rps  # serial spidering is well under typical limits
    try:
        _api("spider", "action", "setOptionThreadCount", {"Integer": 1})
        _api("spider", "action", "setOptionMaxDepth", {"Integer": 5})
        _api("spider", "action", "setOptionMaxDuration", {"Integer": 300})
        _api("spider", "action", "setOptionMaxChildren", {"Integer": 50})
    except ZapError:
        pass


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def _poll_status(component: str, scan_id: str, *, timeout: float,
                 interval: float) -> tuple[int, str]:
    """Poll a spider/ascan status endpoint until 100% or timeout."""
    started = time.monotonic()
    progress = 0
    note = ""
    while True:
        data = _api(component, "view", "status", {"scanId": scan_id})
        progress = int(data.get("status", 0))
        if progress >= 100:
            return progress, note
        if time.monotonic() - started > timeout:
            note = f"timed out after {timeout:.0f}s at {progress}%"
            return progress, note
        time.sleep(interval)


def _start_job(target: str, action: str, job_source: str) -> str:
    jid = jobs.create_job(action, target, source=job_source, agent="ZAP Agent")
    jobs.record_event(jid, {"type": "scan_start", "target": target,
                            "profile": action})
    jobs.record_event(jid, {"type": "plan", "steps": [
        {"key": action, "label": f"ZAP {action}", "agent": "ZAP Agent"},
    ]})
    jobs.record_event(jid, {"type": "step_start", "key": action,
                            "label": f"ZAP {action}", "agent": "ZAP Agent"})
    return jid


def _finish_job(jid: str, action: str, report: ZapReport) -> None:
    jobs.record_event(jid, {"type": "step_end", "key": action,
                            "label": f"ZAP {action}", "agent": "ZAP Agent",
                            "status": "done" if not report.error else "error",
                            "exit_code": 0, "duration_ms": 0,
                            "findings": len(report.alerts)})
    s = report.summary()["by_severity"]
    jobs.record_event(jid, {"type": "scan_done",
                            "status": "done" if not report.error else "error",
                            "findings": {"critical": 0,
                                         "high": s.get("high", 0),
                                         "medium": s.get("medium", 0),
                                         "low": s.get("low", 0),
                                         "info": s.get("info", 0),
                                         "total": len(report.alerts)}})


def _prepare(target: str, action: str, job_source: str) -> ZapReport:
    """Scope-check, then confirm ZAP is reachable."""
    ok, reason = scope.check(target)
    report = ZapReport(target=target, action=action, authorized=ok,
                       scope_reason=reason)
    if not ok:
        return report
    try:
        report.version = _version()
    except ZapError as exc:
        report.available = False
        report.error = str(exc)
    return report


def run_spider(target: str, *, timeout: float = 300,
               poll: float = SPIDER_POLL, job_source: str = "mcp") -> ZapReport:
    """Spider an authorized target, restricted to its ZAP context."""
    report = _prepare(target, "spider", job_source)
    if not report.authorized or not report.available:
        return report

    host = scope.normalize_host(target)
    jid = _start_job(target, "spider", job_source)
    report.job_id = jid
    try:
        # Restrict the spider to the target host, then scan the context.
        rules = scope.get_scope().rules
        _apply_politeness(int(rules.get("max_requests_per_second", 3) or 3))
        ctx = _ensure_context(host)
        data = _api("spider", "action", "scan",
                    {"url": _base_url(target), "contextName": ctx,
                     "recurse": "true"})
        report.scan_id = str(data.get("scan", ""))
        report.progress, note = _poll_status("spider", report.scan_id,
                                             timeout=timeout, interval=poll)
        if note:
            report.error = note
        results = _api("spider", "view", "results",
                       {"scanId": report.scan_id})
        report.urls_found = len(results.get("results", []) or [])
        report.alerts = fetch_alerts(target)
    except ZapError as exc:
        report.error = str(exc)
    _finish_job(jid, "spider", report)
    return report


def run_alerts(target: str, *, job_source: str = "mcp") -> ZapReport:
    """Read ZAP alerts recorded for an authorized target."""
    report = _prepare(target, "alerts", job_source)
    if not report.authorized or not report.available:
        return report
    try:
        report.alerts = fetch_alerts(target)
    except ZapError as exc:
        report.error = str(exc)
    return report


def run_active_scan(target: str, *, confirm_active: bool = False,
                    timeout: float = 900, poll: float = ACTIVE_POLL,
                    job_source: str = "mcp") -> ZapReport:
    """Active scan an authorized target. Requires scope rule + confirmation."""
    report = _prepare(target, "active-scan", job_source)
    if not report.authorized:
        return report
    if not confirm_active:
        report.error = ("refused: active scan requires confirm_active=true "
                        "(it is aggressive — only for programs that allow it)")
        return report
    if not scope.get_scope().rules.get("allow_active_scan", False):
        report.error = ("refused: scope.yaml rules.allow_active_scan is false. "
                        "Enable it only when the program permits active testing.")
        return report
    if not report.available:
        return report

    host = scope.normalize_host(target)
    jid = _start_job(target, "active-scan", job_source)
    report.job_id = jid
    try:
        try:
            _api("ascan", "action", "setOptionDelayInMs", {"Integer": 333})
        except ZapError:
            pass
        ctx = _ensure_context(host)
        data = _api("ascan", "action", "scan",
                    {"url": _base_url(target), "contextName": ctx,
                     "recurse": "true"})
        report.scan_id = str(data.get("scan", ""))
        report.progress, note = _poll_status("ascan", report.scan_id,
                                             timeout=timeout, interval=poll)
        if note:
            report.error = note
        report.alerts = fetch_alerts(target)
    except ZapError as exc:
        report.error = str(exc)
    _finish_job(jid, "active-scan", report)
    return report
