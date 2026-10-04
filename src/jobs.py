"""Cross-process persistent scan status for CLI, MCP, and the web GUI.

SQLite is used so scan progress/history survives GUI restarts and is visible
regardless of which supported entry point launched the scan.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("KPM_JOBS_DB", PROJECT_ROOT / "logs" / "jobs.sqlite3"))
_INIT_LOCK = threading.Lock()
_INITIALIZED_PATH: str | None = None


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


@contextmanager
def _connection():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init() -> None:
    global _INITIALIZED_PATH
    current = str(DB_PATH.resolve())
    if _INITIALIZED_PATH == current:
        return
    with _INIT_LOCK:
        if _INITIALIZED_PATH == current:
            return
        with _connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                profile TEXT NOT NULL,
                target TEXT NOT NULL,
                operator TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'unknown',
                owner_pid INTEGER NOT NULL,
                agent TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'queued',
                started REAL NOT NULL,
                updated REAL NOT NULL,
                finished REAL,
                total INTEGER,
                current TEXT,
                findings_json TEXT,
                report_md TEXT,
                report_json TEXT,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS scan_steps (
                job_id TEXT NOT NULL,
                step_key TEXT NOT NULL,
                order_idx INTEGER NOT NULL DEFAULT 0,
                label TEXT NOT NULL DEFAULT '',
                agent TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                progress INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER,
                exit_code INTEGER,
                findings INTEGER,
                timeout REAL,
                started_at REAL,
                PRIMARY KEY (job_id, step_key),
                FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS scan_jobs_updated_idx
                ON scan_jobs(updated DESC);
            """)
        _INITIALIZED_PATH = current


def create_job(profile: str, target: str, operator: str = "", *,
               source: str = "unknown", job_id: str | None = None,
               agent: str = "") -> str:
    """Create a job (idempotently when *job_id* is supplied)."""
    _init()
    jid = job_id or uuid.uuid4().hex[:12]
    now = time.time()
    with _connection() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO scan_jobs
            (id, profile, target, operator, source, owner_pid, agent,
             status, started, updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)
        """, (jid, profile, target, operator, source, os.getpid(), agent,
              now, now))
    return jid


def _upsert_step(conn: sqlite3.Connection, job_id: str, key: str,
                 *, order_idx: int | None = None, label: str | None = None,
                 agent: str | None = None, status: str | None = None,
                 progress: int | None = None, duration_ms=None, exit_code=None,
                 findings=None, timeout=None, started_at=None) -> None:
    existing = conn.execute(
        "SELECT order_idx FROM scan_steps WHERE job_id=? AND step_key=?",
        (job_id, key),
    ).fetchone()
    row = conn.execute(
        "SELECT COALESCE(MAX(order_idx), -1) + 1 AS next FROM scan_steps WHERE job_id=?",
        (job_id,),
    ).fetchone()
    values = {
        "order_idx": (existing["order_idx"] if existing else row["next"])
                     if order_idx is None else order_idx,
        "label": key if label is None else label,
        "agent": "" if agent is None else agent,
        "status": "pending" if status is None else status,
        "progress": 0 if progress is None else progress,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "findings": findings,
        "timeout": timeout,
        "started_at": started_at,
    }
    conn.execute("""
        INSERT INTO scan_steps
        (job_id, step_key, order_idx, label, agent, status, progress,
         duration_ms, exit_code, findings, timeout, started_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(job_id, step_key) DO UPDATE SET
          order_idx=excluded.order_idx,
          label=CASE WHEN excluded.label='' THEN scan_steps.label ELSE excluded.label END,
          agent=CASE WHEN excluded.agent='' THEN scan_steps.agent ELSE excluded.agent END,
          status=CASE WHEN excluded.status='pending' THEN scan_steps.status ELSE excluded.status END,
          progress=MAX(scan_steps.progress, excluded.progress),
          duration_ms=COALESCE(excluded.duration_ms, scan_steps.duration_ms),
          exit_code=COALESCE(excluded.exit_code, scan_steps.exit_code),
          findings=COALESCE(excluded.findings, scan_steps.findings),
          timeout=COALESCE(excluded.timeout, scan_steps.timeout),
          started_at=COALESCE(excluded.started_at, scan_steps.started_at)
    """, (job_id, key, values["order_idx"], values["label"], values["agent"],
          values["status"], values["progress"], values["duration_ms"],
          values["exit_code"], values["findings"], values["timeout"],
          values["started_at"]))


def record_event(job_id: str, event: dict) -> None:
    """Persist one orchestrator progress event."""
    _init()
    now = time.time()
    kind = event.get("type")
    with _connection() as conn:
        if kind == "scan_start":
            conn.execute("UPDATE scan_jobs SET status='running', updated=? WHERE id=?",
                         (now, job_id))
        elif kind == "plan":
            steps = event.get("steps") or []
            conn.execute("UPDATE scan_jobs SET total=?, status='running', updated=? WHERE id=?",
                         (len(steps), now, job_id))
            for idx, step in enumerate(steps):
                _upsert_step(conn, job_id, step["key"], order_idx=idx,
                             label=step.get("label", step["key"]),
                             agent=step.get("agent", ""),
                             timeout=step.get("timeout"))
        elif kind in ("step_start", "step_end", "step_skipped"):
            key = str(event.get("key") or event.get("tool") or "step")
            state = {
                "step_start": "running",
                "step_end": event.get("status", "done"),
                "step_skipped": "skipped",
            }[kind]
            _upsert_step(
                conn, job_id, key,
                label=event.get("label", key), agent=event.get("agent", ""),
                status=state,
                progress=(100 if kind in ("step_end", "step_skipped") else 0),
                duration_ms=event.get("duration_ms"),
                exit_code=event.get("exit_code"),
                findings=event.get("findings"),
                timeout=event.get("timeout"),
                started_at=(now if kind == "step_start" else None),
            )
            if kind == "step_start":
                conn.execute("UPDATE scan_jobs SET current=?, status='running', updated=? WHERE id=?",
                             (event.get("label", key), now, job_id))
            else:
                conn.execute("UPDATE scan_jobs SET updated=?, current=NULL WHERE id=? AND current=?",
                             (now, job_id, event.get("label", key)))
        elif kind == "scan_done":
            status = event.get("status", "done")
            conn.execute("""
                UPDATE scan_jobs SET status=?, updated=?, finished=?, current=NULL,
                  findings_json=?, report_md=?, report_json=?, error=? WHERE id=?
            """, (status, now, now,
                  json.dumps(event.get("findings")) if event.get("findings") is not None else None,
                  event.get("report_md"), event.get("report_json"),
                  event.get("error"), job_id))
        elif kind == "scan_error":
            conn.execute("UPDATE scan_jobs SET status='error', updated=?, finished=?, error=?, current=NULL WHERE id=?",
                         (now, now, event.get("error", "scan failed"), job_id))


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _snapshot(job_id: str) -> dict | None:
    with _connection() as conn:
        job = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        if job is None:
            return None
        steps = conn.execute(
            "SELECT * FROM scan_steps WHERE job_id=? ORDER BY order_idx, rowid",
            (job_id,),
        ).fetchall()
    now = time.time()
    total = job["total"] or len(steps) or 1
    normalized_steps = []
    completed = 0
    for row in steps:
        step = dict(row)
        if step["status"] in ("done", "error", "skipped", "interrupted"):
            completed += 1
        elif step["status"] == "running" and step["timeout"] and step["started_at"]:
            step["progress"] = min(99, int((now - step["started_at"]) / step["timeout"] * 100))
        normalized_steps.append({
            "key": step["step_key"], "label": step["label"], "agent": step["agent"],
            "status": step["status"], "progress": step["progress"],
            "duration_ms": step["duration_ms"], "exit_code": step["exit_code"],
            "findings": step["findings"], "timeout": step["timeout"],
            "started_at": step["started_at"],
        })
    try:
        findings = json.loads(job["findings_json"]) if job["findings_json"] else None
    except ValueError:
        findings = None
    return {
        "id": job["id"], "profile": job["profile"], "target": job["target"],
        "operator": job["operator"], "source": job["source"],
        "agent": job["agent"], "status": job["status"],
        "total": total, "completed": completed,
        "overall": int(completed / total * 100), "current": job["current"],
        "elapsed": round((job["finished"] or now) - job["started"], 1),
        "steps": normalized_steps, "findings": findings,
        "report_md": job["report_md"], "report_json": job["report_json"],
        "error": job["error"], "updated": job["updated"],
    }


def get_job(job_id: str, *, mark_stale: bool = True) -> dict | None:
    _init()
    with _connection() as conn:
        row = conn.execute("SELECT status, owner_pid FROM scan_jobs WHERE id=?",
                           (job_id,)).fetchone()
        if row and mark_stale and row["status"] in ("queued", "running") and not _pid_alive(row["owner_pid"]):
            now = time.time()
            conn.execute("UPDATE scan_jobs SET status='interrupted', updated=?, finished=?, current=NULL, error='Owning scan process exited before completion' WHERE id=?",
                         (now, now, job_id))
            conn.execute("UPDATE scan_steps SET status='interrupted', progress=100 WHERE job_id=? AND status='running'",
                         (job_id,))
    return _snapshot(job_id)


def list_jobs(limit: int = 100, *, active_only: bool = False) -> list[dict]:
    _init()
    with _connection() as conn:
        ids = [r["id"] for r in conn.execute(
            "SELECT id FROM scan_jobs ORDER BY started DESC LIMIT ?", (limit,)
        ).fetchall()]
    items = [get_job(jid) for jid in ids]
    items = [x for x in items if x]
    if active_only:
        items = [x for x in items if x["status"] in ("queued", "running")]
    return items
