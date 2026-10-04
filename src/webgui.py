"""Web GUI for the pentest framework.

Serves a single-page UI plus a small JSON API, and runs scans in background
threads while streaming per-tool progress. Also lets you view/edit scope.yaml
and download reports. No third-party web deps beyond Starlette/uvicorn (already
pulled in by MCP).

Run:
    python -m src.webgui --host 0.0.0.0 --port 8080
Then open http://<kali-ip>:8080/
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import (FileResponse, HTMLResponse, JSONResponse,
                                 PlainTextResponse)
from starlette.routing import Route

from . import cve as cve_mod
from . import infra as infra_mod
from . import jobs as jobs_mod
from . import matrix as matrix_mod
from . import report as report_mod
from . import scope as scope_mod

SCANS: dict[str, "ScanState"] = {}
_LOCK = threading.Lock()

PROFILES = {
    "matrix": lambda target, operator, emit, job_id: matrix_mod.run_matrix(
        target, operator=operator, on_event=emit, job_id=job_id,
        job_source="webgui"),
    "cve": lambda target, operator, emit, job_id: cve_mod.run_cve_scan(
        target, operator=operator, on_event=emit, job_id=job_id,
        job_source="webgui"),
    "infra": lambda target, operator, emit, job_id: infra_mod.run_infra(
        target, operator=operator, on_event=emit, job_id=job_id,
        job_source="webgui"),
}
LEAD_AGENT = {"matrix": "Matrix Agent", "cve": "CVE Agent",
              "infra": "Infra Agent"}

# Scanner processes we recognise as "a scan" even when started outside the GUI.
_EXT_TOOLS = {"nuclei", "nmap", "nikto", "gobuster", "ffuf", "dirb", "wapiti",
              "wpscan", "sqlmap", "whatweb", "enum4linux", "dnsrecon", "dig",
              "nxc", "netexec", "enum4linux-ng", "snmpwalk", "onesixtyone",
              "showmount", "ike-scan", "sslscan"}
_EXT_AGENT = {
    "whatweb": "Recon Agent", "nmap": "Recon Agent", "dnsrecon": "Recon Agent",
    "dig": "Recon Agent", "gobuster": "Web Agent", "ffuf": "Web Agent",
    "dirb": "Web Agent", "nikto": "Web Agent", "wapiti": "Web Agent",
    "wpscan": "Web Agent", "nuclei": "CVE Agent", "sqlmap": "Exploit Agent",
    "nxc": "Infra Agent", "netexec": "Infra Agent",
    "enum4linux-ng": "Infra Agent", "enum4linux": "Infra Agent",
    "snmpwalk": "Infra Agent", "onesixtyone": "Infra Agent",
    "showmount": "Infra Agent", "ike-scan": "Infra Agent",
    "sslscan": "Infra Agent",
}


def _external_processes() -> list[dict]:
    """Known scanner processes running on the box (may be started outside the GUI)."""
    try:
        out = subprocess.run(["ps", "-eo", "pid,etime,cmd"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:  # noqa: BLE001
        return []
    procs = []
    for line in out.splitlines()[1:]:
        m = re.match(r"\s*(\d+)\s+(\S+)\s+(.*)", line)
        if not m:
            continue
        pid, etime, cmd = m.groups()
        parts = cmd.split()
        tool = os.path.basename(parts[0]) if parts else ""
        if tool not in _EXT_TOOLS or "src.webgui" in cmd:
            continue
        procs.append({"pid": pid, "tool": tool, "etime": etime,
                      "cmd": cmd.strip()})
    return procs


def _etime_seconds(etime: str) -> float:
    days = 0
    if "-" in etime:
        d, etime = etime.split("-", 1)
        try:
            days = int(d)
        except ValueError:
            days = 0
    parts = []
    for x in etime.split(":"):
        try:
            parts.append(int(x))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.insert(0, 0)
    h, m, s = parts[-3:]
    return days * 86400 + h * 3600 + m * 60 + s


def _external_snapshots() -> list[dict]:
    snaps = []
    for p in _external_processes():
        elapsed = _etime_seconds(p["etime"])
        agent = _EXT_AGENT.get(p["tool"], "External")
        snaps.append({
            "id": f"ext-{p['pid']}", "profile": "external",
            "target": p["cmd"][:90], "operator": "", "agent": agent,
            "status": "running", "total": 1, "completed": 0,
            "overall": min(95, int(elapsed / 6)), "current": p["tool"],
            "elapsed": int(elapsed), "external": True,
            "steps": [{
                "key": p["tool"], "label": p["tool"], "agent": agent,
                "status": "running", "progress": min(95, int(elapsed / 6)),
                "duration_ms": None, "exit_code": None, "findings": None,
                "timeout": None, "started_at": None,
            }],
            "findings": None, "report_md": None, "report_json": None,
            "error": None,
        })
    return snaps


class ScanState:
    def __init__(self, profile: str, target: str, operator: str = "",
                 job_id: str | None = None):
        self.id = job_id or uuid.uuid4().hex[:12]
        self.profile = profile
        self.target = target
        self.operator = operator
        self.agent = LEAD_AGENT.get(profile, "Agent")
        self.status = "queued"          # queued|running|done|error
        self.started = time.time()
        self.finished: float | None = None
        self.total: int | None = None
        self.order: list[str] = []
        self.steps: dict[str, dict] = {}
        self.current: str | None = None
        self.findings: dict | None = None
        self.report_md: str | None = None
        self.report_json: str | None = None
        self.error: str | None = None
        self._lock = threading.Lock()

    def _ensure(self, key: str, label: str, timeout=None, agent=None):
        if key not in self.steps:
            self.steps[key] = {
                "key": key, "label": label, "status": "pending",
                "progress": 0, "duration_ms": None, "exit_code": None,
                "findings": None, "timeout": timeout, "started_at": None,
                "agent": agent or "",
            }
        else:
            self.steps[key]["label"] = label
            if timeout is not None:
                self.steps[key]["timeout"] = timeout
            if agent:
                self.steps[key]["agent"] = agent
        if key not in self.order:
            self.order.append(key)

    def emit(self, ev: dict):
        with self._lock:
            t = ev.get("type")
            if t == "scan_start":
                self.status = "running"
            elif t == "plan":
                steps = ev.get("steps", [])
                self.total = len(steps)
                for s in steps:
                    self._ensure(s["key"], s.get("label", s["key"]),
                                 s.get("timeout"), s.get("agent"))
                self.order = [s["key"] for s in steps]
            elif t == "step_start":
                k = ev["key"]
                self._ensure(k, ev.get("label", k), ev.get("timeout"),
                             ev.get("agent"))
                self.steps[k].update(status="running", started_at=time.time(),
                                     timeout=ev.get("timeout"))
                self.current = k
            elif t == "step_end":
                k = ev["key"]
                self._ensure(k, ev.get("label", k), agent=ev.get("agent"))
                self.steps[k].update(
                    status=ev.get("status", "done"), progress=100,
                    duration_ms=ev.get("duration_ms"),
                    exit_code=ev.get("exit_code"),
                    findings=ev.get("findings"))
                if self.current == k:
                    self.current = None
            elif t == "step_skipped":
                k = ev["key"]
                self._ensure(k, ev.get("label", k), agent=ev.get("agent"))
                self.steps[k].update(status="skipped", progress=100)
            elif t == "scan_done":
                self.status = "done"
                self.finished = time.time()
                self.findings = ev.get("findings")
                self.report_md = ev.get("report_md")
                self.report_json = ev.get("report_json")

    def fail(self, exc: Exception):
        with self._lock:
            self.status = "error"
            self.error = f"{type(exc).__name__}: {exc}"
            self.finished = time.time()

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            steps = []
            completed = 0
            for key in self.order:
                s = dict(self.steps[key])
                if s["status"] in ("done", "error", "skipped"):
                    completed += 1
                elif s["status"] == "running" and s.get("timeout") and s.get("started_at"):
                    frac = (now - s["started_at"]) / float(s["timeout"])
                    s["progress"] = min(99, int(frac * 100))
                steps.append(s)
            total = self.total or len(steps) or 1
            return {
                "id": self.id,
                "profile": self.profile,
                "target": self.target,
                "operator": self.operator,
                "agent": self.agent,
                "status": self.status,
                "total": total,
                "completed": completed,
                "overall": int(completed / total * 100),
                "current": self.current,
                "elapsed": round(now - self.started, 1),
                "steps": steps,
                "findings": self.findings,
                "report_md": self.report_md,
                "report_json": self.report_json,
                "error": self.error,
            }


def _start_scan(profile: str, target: str, operator: str = "",
                job_id: str | None = None) -> ScanState:
    scan = ScanState(profile, target, operator, job_id=job_id)
    with _LOCK:
        SCANS[scan.id] = scan

    def worker():
        scan.emit({"type": "scan_start", "target": target, "profile": profile})
        try:
            PROFILES[profile](target, operator, scan.emit, scan.id)
        except Exception as exc:  # noqa: BLE001
            try:
                jobs_mod.record_event(scan.id, {
                    "type": "scan_error",
                    "error": f"{type(exc).__name__}: {exc}",
                })
            except Exception:  # noqa: BLE001
                pass
            scan.fail(exc)

    threading.Thread(target=worker, daemon=True).start()
    return scan


def _reports_dir() -> Path:
    return report_mod.REPORTS_DIR


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

async def index(request):
    return HTMLResponse(PAGE)


async def api_scope(request):
    sc = scope_mod.get_scope(force=True)
    return JSONResponse({
        "source": sc.source,
        "program": sc.program,
        "rules": sc.rules,
        "in_scope": sc.entries(),
    })


async def api_scope_raw(request):
    path = scope_mod.SCOPE_YAML
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    return PlainTextResponse(text)


async def api_scope_save(request):
    data = await request.json()
    text = data.get("yaml") or ""
    try:
        import yaml
        parsed = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"YAML parse error: {exc}"},
                            status_code=400)
    if not isinstance(parsed, dict):
        return JSONResponse({"error": "scope must be a YAML mapping"},
                            status_code=400)
    if "in_scope" not in parsed:
        return JSONResponse(
            {"error": "scope must contain an 'in_scope' section"},
            status_code=400)

    path = scope_mod.SCOPE_YAML
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    sc = scope_mod.get_scope(force=True)
    return JSONResponse({"ok": True, "source": str(path),
                         "in_scope": sc.entries()})


async def api_scope_check(request):
    target = request.query_params.get("target", "")
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)
    ok, reason = scope_mod.check(target)
    return JSONResponse({"allowed": ok, "reason": reason})


async def api_start(request):
    data = await request.json()
    profile = (data.get("profile") or "matrix").lower()
    target = (data.get("target") or "").strip()
    operator = (data.get("operator") or "").strip()
    if profile not in PROFILES:
        return JSONResponse({"error": f"unknown profile {profile}"},
                            status_code=400)
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)
    ok, reason = scope_mod.check(target)
    if not ok:
        return JSONResponse({"error": f"target not authorized: {reason}"},
                            status_code=403)
    job_id = jobs_mod.create_job(profile, target, operator, source="webgui",
                                 agent=LEAD_AGENT.get(profile, "Agent"))
    scan = _start_scan(profile, target, operator, job_id=job_id)
    return JSONResponse({"id": scan.id})


async def api_scans(request):
    persisted = jobs_mod.list_jobs(limit=100)
    live = [s for s in persisted if s["status"] in ("running", "queued")]
    # Raw tools started outside an orchestrator remain visible as a fallback.
    items = list(live)
    if not live:
        items += _external_snapshots()
        items += persisted
    return JSONResponse({"scans": items})


async def api_scan(request):
    sid = request.path_params["sid"]
    if sid.startswith("ext-"):
        for s in _external_snapshots():
            if s["id"] == sid:
                return JSONResponse(s)
        return JSONResponse({
            "id": sid, "profile": "external", "target": "", "operator": "",
            "agent": "External", "status": "done", "total": 1, "completed": 1,
            "overall": 100, "current": None, "elapsed": 0, "steps": [],
            "findings": None, "report_md": None, "report_json": None,
            "error": None})
    persisted = jobs_mod.get_job(sid)
    if persisted:
        return JSONResponse(persisted)
    scan = SCANS.get(sid)
    if not scan:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(scan.snapshot())


async def api_scan_report(request):
    sid = request.path_params["sid"]
    scan = jobs_mod.get_job(sid) or SCANS.get(sid)
    report_md = scan.get("report_md") if isinstance(scan, dict) else getattr(scan, "report_md", None)
    if not report_md:
        return PlainTextResponse("report not ready", status_code=404)
    path = Path(report_md)
    if not path.exists():
        return PlainTextResponse("report file missing", status_code=404)
    return PlainTextResponse(path.read_text(encoding="utf-8", errors="replace"))


async def api_scan_download(request):
    sid = request.path_params["sid"]
    scan = jobs_mod.get_job(sid) or SCANS.get(sid)
    report_md = scan.get("report_md") if isinstance(scan, dict) else getattr(scan, "report_md", None)
    report_json = scan.get("report_json") if isinstance(scan, dict) else getattr(scan, "report_json", None)
    if not report_md or not Path(report_md).exists():
        return JSONResponse({"error": "report not ready"}, status_code=404)
    fmt = request.query_params.get("fmt", "md")
    path = Path(report_json if (fmt == "json" and report_json) else report_md)
    if not path.exists():
        return JSONResponse({"error": "file missing"}, status_code=404)
    media_type = "application/json" if path.suffix == ".json" else "text/markdown"
    return FileResponse(str(path), filename=path.name, media_type=media_type)


async def api_reports(request):
    d = _reports_dir()
    items = []
    if d.exists():
        files = [p for p in d.glob("*") if p.suffix in (".md", ".json")]
        for p in sorted(files, key=lambda x: x.stat().st_mtime,
                        reverse=True)[:100]:
            st = p.stat()
            items.append({"name": p.name, "size": st.st_size,
                          "mtime": st.st_mtime})
    return JSONResponse({"reports": items})


async def api_report_download(request):
    name = request.query_params.get("name", "")
    base = Path(name).name
    root = _reports_dir().resolve()
    path = (root / base).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return JSONResponse({"error": "invalid path"}, status_code=400)
    if not path.exists() or path.suffix not in (".md", ".json"):
        return JSONResponse({"error": "not found"}, status_code=404)
    mt = "text/markdown" if path.suffix == ".md" else "application/json"
    return FileResponse(str(path), filename=path.name, media_type=mt)


routes = [
    Route("/", index),
    Route("/api/scope", api_scope),
    Route("/api/scope/raw", api_scope_raw),
    Route("/api/scope/save", api_scope_save, methods=["POST"]),
    Route("/api/scope/check", api_scope_check),
    Route("/api/scans", api_scans),
    Route("/api/scan", api_start, methods=["POST"]),
    Route("/api/scan/{sid}", api_scan),
    Route("/api/scan/{sid}/report", api_scan_report),
    Route("/api/scan/{sid}/download", api_scan_download),
    Route("/api/reports", api_reports),
    Route("/api/reports/download", api_report_download),
]

app = Starlette(routes=routes)


PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>KALI·PENTEST — Scan Console</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap');
 /* Design system generated with ui-ux-pro-max — "Cyberpunk UI" (Cybersecurity Platform) */
 :root{
   --bg:#000000; --bg2:#0c130e; --panel:rgba(12,19,14,.86); --line:rgba(0,255,65,.18);
   --grn:#00ff41; --cyn:#22d3ee; --amb:#ffb020; --red:#ef4444; --pur:#a855f7;
   --fg:#e0e0e0; --mut:#94a3b8;
   --ring:#00ff41; --radius:8px;
 }
 *{box-sizing:border-box}
 body{margin:0;color:var(--fg);font:14px/1.55 "Fira Sans",ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif;
   background:
     radial-gradient(1200px 600px at 20% -10%, rgba(0,255,65,.08), transparent 60%),
     radial-gradient(900px 500px at 100% 0%, rgba(34,211,238,.06), transparent 55%),
     linear-gradient(rgba(0,255,65,.03) 1px, transparent 1px) 0 0/100% 26px,
     linear-gradient(90deg, rgba(0,255,65,.03) 1px, transparent 1px) 0 0/26px 100%,
     var(--bg);
 }
 h1,button,th,.badge,.meta,.live,.hint,code,label{font-family:"Fira Code",ui-monospace,SFMono-Regular,Consolas,monospace}
 body:after{content:"";position:fixed;inset:0;pointer-events:none;z-index:5;
   background:repeating-linear-gradient(0deg, rgba(0,0,0,.16) 0 1px, transparent 1px 3px);opacity:.45}
 header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center;
   flex-wrap:wrap;background:linear-gradient(180deg, rgba(0,255,156,.06), transparent);position:relative;z-index:6}
 h1{font-size:15px;margin:0 16px 0 0;letter-spacing:2px;color:var(--grn);
   text-shadow:0 0 8px rgba(0,255,156,.65);text-transform:uppercase}
 .dots{display:inline-flex;gap:6px;margin-right:10px;vertical-align:middle}
 .dots i{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--red);box-shadow:0 0 6px var(--red)}
 .dots i:nth-child(2){background:var(--amb);box-shadow:0 0 6px var(--amb)}
 .dots i:nth-child(3){background:var(--grn);box-shadow:0 0 6px var(--grn)}
 input,select,textarea{background:rgba(0,0,0,.45);color:var(--fg);border:1px solid var(--line);border-radius:4px;
   padding:8px 10px;font-family:inherit;outline:none}
 input:focus,select:focus,textarea:focus{border-color:var(--grn);box-shadow:0 0 0 2px rgba(0,255,156,.15)}
 textarea{width:100%;min-height:360px;font-size:12.5px;line-height:1.45}
 button{background:linear-gradient(180deg, rgba(0,255,156,.22), rgba(0,255,156,.08));color:var(--grn);
   border:1px solid var(--grn);border-radius:4px;padding:8px 14px;cursor:pointer;font-weight:700;
   letter-spacing:1px;text-transform:uppercase;font-family:inherit}
 button:hover{box-shadow:0 0 12px rgba(0,255,156,.5);background:rgba(0,255,156,.2)}
 button.sec{background:rgba(34,211,238,.08);color:var(--cyn);border-color:var(--cyn)}
 button.sec:hover{box-shadow:0 0 12px rgba(34,211,238,.5)}
 button:disabled{opacity:.45;cursor:not-allowed;box-shadow:none}
 main{padding:20px;max-width:1180px;margin:0 auto;position:relative;z-index:6}
 .bar{height:24px;background:rgba(0,0,0,.5);border:1px solid var(--line);border-radius:4px;overflow:hidden;position:relative}
 .bar>span{display:block;height:100%;width:0;transition:width .5s;
   background:repeating-linear-gradient(45deg, rgba(0,255,156,.95) 0 10px, rgba(0,255,156,.6) 10px 20px);
   box-shadow:0 0 14px rgba(0,255,156,.7)}
 .bar>b{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:12px;
   font-weight:700;letter-spacing:1px;text-shadow:0 0 6px #000}
 .meta{display:flex;gap:22px;color:var(--mut);margin:10px 0 18px;flex-wrap:wrap;font-size:12.5px}
 .meta b{color:var(--fg)}
 table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}
 th,td{padding:9px 12px;border-bottom:1px solid rgba(0,255,156,.10);text-align:left;font-size:12.5px;vertical-align:middle}
 th{background:rgba(0,255,156,.06);color:var(--grn);font-weight:700;letter-spacing:1px;text-transform:uppercase;font-size:11px}
 tr:hover td{background:rgba(0,255,156,.04)}
 td.bar-cell{width:210px}
 .mini{height:9px;background:rgba(0,0,0,.5);border:1px solid var(--line);border-radius:4px;overflow:hidden}
 .mini>span{display:block;height:100%;width:0;transition:width .5s}
 .badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:10.5px;font-weight:700;
   letter-spacing:.5px;text-transform:uppercase;border:1px solid transparent}
 .pending{background:rgba(255,255,255,.05);color:var(--mut);border-color:#2a3a36}
 .running{background:rgba(34,211,238,.15);color:var(--cyn);border-color:var(--cyn);animation:pulse 1.2s infinite}
 .done{background:rgba(0,255,156,.14);color:var(--grn);border-color:var(--grn)}
 .error{background:rgba(255,59,78,.16);color:var(--red);border-color:var(--red)}
 .skipped{background:rgba(255,255,255,.05);color:var(--mut);border-color:#2a3a36}
 .interrupted{background:rgba(255,176,32,.14);color:var(--amb);border-color:var(--amb)}
 @keyframes pulse{0%,100%{box-shadow:0 0 0 rgba(34,211,238,0)}50%{box-shadow:0 0 10px rgba(34,211,238,.6)}}
 .agent{white-space:nowrap;font-size:11.5px}
 .agent i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
 .card{margin-top:18px;padding:14px 16px;background:var(--panel);border:1px solid var(--line);border-radius:6px}
 .sev{display:inline-block;margin-right:14px;font-weight:700}
 a{color:var(--cyn)} .hint{color:var(--mut);font-size:12px;margin:6px 0}
 .ok{color:var(--grn)} .bad{color:var(--red)}
 .dl{margin-left:10px;background:rgba(0,255,156,.16);border:1px solid var(--grn);padding:6px 12px;border-radius:4px;
   color:var(--grn);text-decoration:none;font-weight:700;font-size:12px}
 .dl:hover{box-shadow:0 0 10px rgba(0,255,156,.5)}
 .rep{margin:6px 0;display:flex;gap:12px;align-items:center;border-bottom:1px dashed rgba(0,255,156,.12);padding-bottom:6px}
 .rep .nm{flex:1;word-break:break-all;color:var(--fg)}
 .live{color:var(--grn);font-weight:700;letter-spacing:1px}
 .live:before{content:"● ";color:var(--grn);text-shadow:0 0 8px var(--grn)}
 /* --- ui-ux-pro-max refinements ------------------------------------- */
 :focus-visible{outline:2px solid var(--ring);outline-offset:2px;border-radius:4px}
 button,a,input,select,textarea{transition:background .18s ease,border-color .18s ease,box-shadow .18s ease,color .18s ease}
 button,a{cursor:pointer}
 .tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:6px}
 .icn{width:16px;height:16px;vertical-align:-3px;margin-right:6px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
 .brand{width:20px;height:20px;vertical-align:-4px;margin-right:8px;color:var(--grn);filter:drop-shadow(0 0 6px rgba(0,255,65,.6));fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
 @media (max-width:640px){ main{padding:14px} h1{font-size:13px} .meta{gap:14px} td.bar-cell{width:150px} }
 @media (prefers-reduced-motion: reduce){
   *{animation:none !important;transition:none !important}
   body:after{display:none}
 }
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
 <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/></symbol>
 <symbol id="i-scan" viewBox="0 0 24 24"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M3 12h18"/></symbol>
 <symbol id="i-scope" viewBox="0 0 24 24"><path d="M4 5h16"/><path d="M4 12h10"/><path d="M4 19h7"/><circle cx="18" cy="16" r="3"/><path d="M20.5 18.5L23 21"/></symbol>
 <symbol id="i-play" viewBox="0 0 24 24"><path d="M6 4l14 8-14 8z"/></symbol>
 <symbol id="i-save" viewBox="0 0 24 24"><path d="M5 3h11l3 3v15H5z"/><path d="M8 3v6h7V3"/><path d="M8 15h8"/></symbol>
 <symbol id="i-refresh" viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 4v4h-4"/></symbol>
 <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></symbol>
 <symbol id="i-download" viewBox="0 0 24 24"><path d="M12 3v12"/><path d="M7 12l5 5 5-5"/><path d="M5 21h14"/></symbol>
</defs></svg>
<header>
  <h1><svg class="brand" aria-hidden="true"><use href="#i-shield"/></svg>KALI·PENTEST</h1>
  <span class="live" id="live" style="display:none">LIVE SCAN</span>
  <span class="live" id="globalRun" style="display:none;color:#ffb020">0 RUNNING</span>
  <span style="flex:1"></span>
  <button class="sec" id="tabScan"><svg class="icn" aria-hidden="true"><use href="#i-scan"/></svg>Scan</button>
  <button class="sec" id="tabScope"><svg class="icn" aria-hidden="true"><use href="#i-scope"/></svg>Scope</button>
</header>
<main>
 <div id="viewScan">
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px">
    <input id="target" placeholder="target // must be in scope" value="www.vulnbank.org" size="32" aria-label="Target">
    <select id="profile" aria-label="Scan profile">
      <option value="matrix">matrix — all tools</option>
      <option value="cve">cve — nuclei + nmap vuln</option>
      <option value="infra">infra — SMB/SNMP/SSH/RDP/VPN</option>
    </select>
    <input id="operator" placeholder="operator" value="review" size="10" aria-label="Operator">
    <button id="start"><svg class="icn" aria-hidden="true"><use href="#i-play"/></svg>Start scan</button>
  </div>
  <div class="bar"><span id="obar"></span><b id="otxt">IDLE</b></div>
  <div class="meta" role="status" aria-live="polite">
    <span>STATUS <b id="mstatus">—</b></span>
    <span>AGENT <b id="magent">—</b></span>
    <span>TARGET <b id="mtarget">—</b></span>
    <span>NOW <b id="mcur">—</b></span>
    <span>T+ <b id="melapsed">0s</b></span>
  </div>
  <div class="tablewrap">
  <table><thead><tr><th scope="col">Agent</th><th scope="col">Tool</th><th scope="col">Status</th><th scope="col">Progress</th>
    <th scope="col">Duration</th><th scope="col">Exit</th><th scope="col">Findings</th></tr></thead>
    <tbody id="rows"><tr><td colspan="7" style="color:var(--mut)">// no scan yet — configure a target and hit START</td></tr></tbody></table>
  </div>
  <div class="card" id="sum" style="display:none"></div>
 </div>

 <div id="viewScope" style="display:none">
   <div class="hint">// editing <b>scope.yaml</b> (authoritative). SAVE validates the YAML and hot-reloads the scope.</div>
   <textarea id="scopeYaml" spellcheck="false" aria-label="scope.yaml contents"></textarea>
   <div style="display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap">
     <button id="saveScope"><svg class="icn" aria-hidden="true"><use href="#i-save"/></svg>Save scope</button>
     <button class="sec" id="reloadScope"><svg class="icn" aria-hidden="true"><use href="#i-refresh"/></svg>Reload</button>
     <input id="checkTarget" placeholder="target to check" size="26" aria-label="Target to check">
     <button class="sec" id="checkBtn"><svg class="icn" aria-hidden="true"><use href="#i-search"/></svg>Scope check</button>
     <span id="scopeMsg" role="status" aria-live="polite"></span>
   </div>
 </div>

 <div class="card">
   <b>// RECENT REPORTS</b>
   <div class="hint">Latest reports on the server — click to download.</div>
   <div id="reports"></div>
 </div>
</main>
<script>
const $=id=>document.getElementById(id);
const sev=["critical","high","medium","low","info"];
const col={critical:"#ef4444",high:"#ff8a3d",medium:"#ffb020",low:"#22d3ee",info:"#94a3b8"};
const agentCol={"Recon Agent":"#22d3ee","Web Agent":"#00ff41","CVE Agent":"#ffb020",
  "Exploit Agent":"#ef4444","Matrix Agent":"#a855f7","Infra Agent":"#f59e0b"};
let sid=null, timer=null;

$("tabScan").onclick=()=>{$("viewScan").style.display="";$("viewScope").style.display="none";};
$("tabScope").onclick=()=>{$("viewScan").style.display="none";$("viewScope").style.display="";loadScope();};
$("reloadScope").onclick=loadScope;
$("saveScope").onclick=saveScope;
$("checkBtn").onclick=scopeCheck;

function agentChip(name){const c=agentCol[name]||"#5f7d74";return '<span class="agent" style="color:'+c+'"><i style="background:'+c+';box-shadow:0 0 6px '+c+'"></i>'+name+'</span>';}

async function loadScope(){const r=await fetch("/api/scope/raw"); $("scopeYaml").value=await r.text();}
async function saveScope(){
  $("scopeMsg").textContent="saving…"; $("scopeMsg").className="";
  const r=await fetch("/api/scope/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({yaml:$("scopeYaml").value})});
  const j=await r.json();
  if(j.error){$("scopeMsg").textContent="✗ "+j.error;$("scopeMsg").className="bad";}
  else{$("scopeMsg").textContent="✓ saved — in scope: "+(j.in_scope||[]).join(", ");$("scopeMsg").className="ok";}
}
async function scopeCheck(){
  const t=$("checkTarget").value.trim(); if(!t)return;
  const r=await fetch("/api/scope/check?target="+encodeURIComponent(t)); const j=await r.json();
  $("scopeMsg").textContent=(j.allowed?"✓ AUTHORIZED — ":"⛔ DENIED — ")+j.reason;
  $("scopeMsg").className=j.allowed?"ok":"bad";
}

$("start").onclick=async()=>{
  $("start").disabled=true;
  const body={target:$("target").value.trim(),profile:$("profile").value,operator:$("operator").value.trim()};
  const r=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const j=await r.json(); $("start").disabled=false;
  if(j.error){alert(j.error);return;}
  $("rows").innerHTML="";$("sum").style.display="none";
  attach(j.id);
};

async function poll(){
  if(!sid)return;
  const r=await fetch("/api/scan/"+sid); if(!r.ok)return;
  const s=await r.json();
  $("mstatus").textContent=s.status.toUpperCase();
  $("magent").innerHTML=agentChip(s.agent||"Agent");
  $("mtarget").textContent=s.target||"—";
  $("mcur").textContent=s.current||"—";
  $("melapsed").textContent=s.elapsed+"s";
  $("obar").style.width=s.overall+"%";
  $("otxt").textContent=s.overall+"%  ["+s.completed+"/"+s.total+"]";
  const tb=$("rows");
  s.steps.forEach(st=>{
    let tr=document.getElementById("row-"+st.key);
    if(!tr){tr=document.createElement("tr");tr.id="row-"+st.key;
      tr.innerHTML='<td class="ag"></td><td>'+st.label+'</td><td class="st"></td><td class="bar-cell"><div class="mini"><span></span></div></td><td class="du"></td><td class="ex"></td><td class="fi"></td>';
      tb.appendChild(tr);}
    tr.querySelector(".ag").innerHTML=agentChip(st.agent||s.agent||"");
    tr.querySelector(".st").innerHTML='<span class="badge '+st.status+'">'+st.status+'</span>';
    const bar=tr.querySelector(".mini>span");
    bar.style.width=(st.progress||0)+"%";
    const bc=(st.status==="error")?"#ef4444":(st.status==="done")?"#00ff41":(st.status==="skipped")?"#94a3b8":(st.status==="interrupted")?"#ffb020":"#22d3ee";
    bar.style.background=bc;bar.style.boxShadow="0 0 8px "+bc;
    tr.querySelector(".du").textContent=st.duration_ms!=null?(st.duration_ms/1000).toFixed(1)+"s":"—";
    tr.querySelector(".ex").textContent=st.exit_code!=null?st.exit_code:"—";
    tr.querySelector(".fi").textContent=st.findings!=null?st.findings:"—";
  });
  if(s.findings){
    $("sum").style.display="block";
    $("sum").innerHTML="<b>// FINDINGS</b> "+sev.map(k=>'<span class="sev" style="color:'+col[k]+'">'+k+"="+(s.findings[k]||0)+"</span>").join("")+
      (s.status==="done"?('<a class="dl" href="/api/scan/'+s.id+'/download?fmt=md"><svg class="icn" aria-hidden="true"><use href="#i-download"/></svg>REPORT .MD</a> <a class="dl" style="color:#22d3ee;border-color:#22d3ee" href="/api/scan/'+s.id+'/download?fmt=json"><svg class="icn" aria-hidden="true"><use href="#i-download"/></svg>JSON</a>'):"");
    loadReports();
  }
  if(s.status==="error")$("sum").innerHTML="<b style='color:#ff3b4e'>// ERROR</b> "+s.error;
  if(s.status==="done"||s.status==="error"||s.status==="interrupted"){clearInterval(timer);timer=null;$("live").style.display="none";}
}

function attach(id){
  sid=id;
  if(timer)clearInterval(timer);
  timer=setInterval(poll,1000);
  $("live").style.display="";
  poll();
}

// Auto-attach to any running scan and keep the header indicator live.
async function globalWatch(){
  try{
    const j=await (await fetch("/api/scans")).json();
    const running=(j.scans||[]).filter(s=>s.status==="running"||s.status==="queued");
    const g=$("globalRun");
    if(running.length){g.style.display="";g.textContent="● "+running.length+" RUNNING";}
    else{g.style.display="none";}
    if(running.length && !running.some(s=>s.id===sid)){ attach(running[0].id); }
    else if(!sid && (j.scans||[]).length){ attach(j.scans[0].id); }
  }catch(e){}
}
setInterval(globalWatch,4000); globalWatch();

async function loadReports(){
  const r=await fetch("/api/reports"); if(!r.ok)return;
  const j=await r.json();
  $("reports").innerHTML=(j.reports||[]).map(x=>
    '<div class="rep"><span class="nm">'+x.name+'</span>'+
    '<a href="/api/reports/download?name='+encodeURIComponent(x.name)+'">DOWNLOAD</a></div>').join("")||"<span class=hint>none</span>";
}
loadReports();
</script></body></html>
"""


def main() -> int:
    import uvicorn
    ap = argparse.ArgumentParser(prog="src.webgui")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
