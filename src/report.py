"""Review-ready reporting: Markdown + machine-readable JSON."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .findings import Finding, SEVERITIES, summarize

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

_SEV_BADGE = {
    "critical": "🟥 CRITICAL",
    "high": "🟧 HIGH",
    "medium": "🟨 MEDIUM",
    "low": "🟦 LOW",
    "info": "⬜ INFO",
}


@dataclass
class Assessment:
    target: str
    profile: str = "web"
    job_id: str = ""
    authorized: bool = False
    scope_reason: str = ""
    operator: str = ""
    program: dict = field(default_factory=dict)
    rules: dict = field(default_factory=dict)
    started: str = ""
    finished: str = ""
    commands: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)
    notes: str = ""
    report_md: str = ""
    report_json: str = ""

    # ------------------------------------------------------------------
    def summary(self) -> dict:
        return summarize(self.findings)

    def to_json(self) -> dict:
        return {
            "meta": {
                "target": self.target,
                "profile": self.profile,
                "job_id": self.job_id,
                "authorized": self.authorized,
                "scope_reason": self.scope_reason,
                "operator": self.operator,
                "program": self.program,
                "rules": self.rules,
                "started": self.started,
                "finished": self.finished,
                "generated": datetime.now(timezone.utc).isoformat(),
                "tool": "kali-pentest-mcp",
            },
            "summary": self.summary(),
            "commands": self.commands,
            "artifacts": self.artifacts,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "target"


def _fence(text: str, limit: int = 4000) -> str:
    text = (text or "").strip()
    if len(text) > limit:
        text = text[:limit] + "\n...[truncated]"
    text = text.replace("```", "'''")
    return f"```text\n{text}\n```"


def render_markdown(a: Assessment) -> str:
    s = a.summary()
    prog = a.program or {}
    rules = a.rules or {}

    lines: list[str] = []
    lines.append(f"# 🛡️ Security Assessment Report — `{a.target}`")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Target | `{a.target}` |")
    lines.append(f"| Profile | `{a.profile}` |")
    lines.append(f"| Program | {prog.get('name', '—')} |")
    lines.append(f"| Platform | {prog.get('platform', '—')} |")
    lines.append(f"| Authorization | {prog.get('authorization', '—')} |")
    lines.append(f"| Operator | {a.operator or '—'} |")
    lines.append(f"| Started | {a.started or '—'} |")
    lines.append(f"| Finished | {a.finished or '—'} |")
    lines.append(f"| Scope decision | {'✅ AUTHORIZED' if a.authorized else '⛔ DENIED'} — {a.scope_reason} |")
    lines.append("")

    if not a.authorized:
        lines.append("> **No scanning was performed.** The target is not authorized "
                     "by the active scope (`scope.yaml` / `scope.txt`).")
        lines.append("")
        return "\n".join(lines)

    # --- Rules of engagement -----------------------------------------
    if rules:
        lines.append("## 📜 Rules of Engagement")
        lines.append("")
        for k, v in rules.items():
            lines.append(f"- **{k}**: `{v}`")
        lines.append("")

    # --- Summary ------------------------------------------------------
    lines.append("## 📊 Findings Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for sev in SEVERITIES:
        lines.append(f"| {_SEV_BADGE[sev]} | {s.get(sev, 0)} |")
    lines.append(f"| **Total** | **{s.get('total', 0)}** |")
    lines.append("")

    # --- Findings table ----------------------------------------------
    if a.findings:
        lines.append("## 🔎 Findings")
        lines.append("")
        for i, f in enumerate(a.findings, 1):
            lines.append(f"### {i}. {_SEV_BADGE.get(f.severity, f.severity)} — {f.title}")
            lines.append("")
            lines.append(f"- **Endpoint**: `{f.endpoint or a.target}`")
            tools = ", ".join(f.sources or [f.tool])
            lines.append(f"- **Tools**: `{tools}`  |  **Confidence**: {f.confidence}"
                         f"  |  **Validation**: {f.validation_status}"
                         + (f"  |  **Port**: {f.port}" if f.port else ""))
            if f.description:
                lines.append(f"- **Description**: {f.description}")
            lines.append("")
            if f.evidence:
                lines.append("**Evidence**")
                lines.append("")
                lines.append(_fence(f.evidence, 1500))
                lines.append("")
            if f.remediation:
                lines.append(f"**Remediation**: {f.remediation}")
                lines.append("")
            if f.references:
                lines.append("**References**: " + ", ".join(f.references))
                lines.append("")
    else:
        lines.append("## 🔎 Findings")
        lines.append("")
        lines.append("No findings were derived from the collected output. Raw output is in the appendix.")
        lines.append("")

    # --- Methodology --------------------------------------------------
    lines.append("## 🧪 Methodology")
    lines.append("")
    lines.append("| Tool | Command | Exit | Duration (ms) | Artifact |")
    lines.append("| --- | --- | ---: | ---: | --- |")
    for c in a.commands:
        cmd = c.get("command", "").replace("|", "\\|")
        lines.append(f"| {c.get('tool', '')} | `{cmd}` | {c.get('exit_code', '')} "
                     f"| {c.get('duration_ms', '')} | {c.get('artifact', '') or '—'} |")
    lines.append("")

    # --- Appendix -----------------------------------------------------
    if a.raw:
        lines.append("## 📎 Appendix — Raw Output")
        lines.append("")
        for tool, out in a.raw.items():
            lines.append(f"### {tool}")
            lines.append("")
            lines.append(_fence(out, 6000))
            lines.append("")

    if a.notes:
        lines.append("## 📝 Notes")
        lines.append("")
        lines.append(a.notes)
        lines.append("")

    return "\n".join(lines)


def write_report(a: Assessment, reports_dir: Path | None = None) -> tuple[str, str]:
    """Write ``<target>_<timestamp>.md`` and ``.json``; return their paths."""
    out_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"{_safe_name(a.target)}_{a.profile}_{stamp}"

    md_path = out_dir / f"{base}.md"
    json_path = out_dir / f"{base}.json"

    md_path.write_text(render_markdown(a), encoding="utf-8")
    json_path.write_text(json.dumps(a.to_json(), indent=2), encoding="utf-8")
    return str(md_path), str(json_path)


def load_assessment(json_path: str | Path) -> Assessment:
    """Rebuild an :class:`Assessment` from a previously written JSON file."""
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    meta = data.get("meta", {})
    fields = Finding.__dataclass_fields__
    fs = [
        Finding(**{k: v for k, v in f.items() if k in fields})
        for f in data.get("findings", [])
    ]
    return Assessment(
        target=meta.get("target", ""),
        profile=meta.get("profile", ""),
        job_id=meta.get("job_id", ""),
        authorized=bool(meta.get("authorized", False)),
        scope_reason=meta.get("scope_reason", ""),
        operator=meta.get("operator", ""),
        program=meta.get("program", {}) or {},
        rules=meta.get("rules", {}) or {},
        started=meta.get("started", ""),
        finished=meta.get("finished", ""),
        commands=data.get("commands", []) or [],
        findings=fs,
        artifacts=data.get("artifacts", []) or [],
        notes=data.get("notes", ""),
    )
