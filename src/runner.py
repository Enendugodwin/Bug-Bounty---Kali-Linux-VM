"""
Subprocess executor: rate-limited, timeout-bounded, audit-logged.

Returns a structured result so the LLM can reason about outcomes.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ARTIFACT_DIR = PROJECT_ROOT / "artifacts"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG = LOG_DIR / "audit.log"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = int(
    os.getenv("PENTEST_CMD_TIMEOUT", "900")
)

RATE_PER_MIN = int(
    os.getenv("PENTEST_RATE_PER_MIN", "10")
)

MAX_CAPTURE_BYTES = 2_000_000


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    """Structured result returned after command execution."""

    command: list[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    artifact_path: str | None = None
    truncated: bool = False


# ---------------------------------------------------------------------------
# Token bucket rate limiter
# ---------------------------------------------------------------------------

class _TokenBucket:
    """Simple thread-safe token bucket rate limiter."""

    def __init__(self, rate_per_min: int):
        if rate_per_min <= 0:
            raise ValueError(
                "PENTEST_RATE_PER_MIN must be greater than 0"
            )

        self.rate = rate_per_min / 60.0
        self.capacity = float(rate_per_min)
        self.tokens = float(rate_per_min)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def take(self, n: float = 1.0) -> None:
        """Wait until enough tokens are available."""

        if n <= 0:
            return

        while True:
            with self.lock:
                now = time.monotonic()

                elapsed = now - self.last

                self.tokens = min(
                    self.capacity,
                    self.tokens + elapsed * self.rate,
                )

                self.last = now

                if self.tokens >= n:
                    self.tokens -= n
                    return

                wait = (n - self.tokens) / self.rate

            time.sleep(min(wait, 1.0))


_bucket = _TokenBucket(RATE_PER_MIN)


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def _audit(record: dict) -> None:
    """Append a command execution record to audit.log."""

    timestamp = time.strftime(
        "%Y-%m-%dT%H:%M:%S%z"
    )

    command = " ".join(
        shlex.quote(str(arg))
        for arg in record["command"]
    )

    line = (
        f"{timestamp}\t"
        f"{record['id']}\t"
        f"{command}\n"
    )

    with AUDIT_LOG.open(
        "a",
        encoding="utf-8",
    ) as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# Command validation
# ---------------------------------------------------------------------------

def _validate_command(cmd: Sequence[str]) -> list[str]:
    """
    Validate and normalize a command.

    Commands must be provided as an argv sequence.
    Shell command strings are not accepted.
    """

    command = [str(arg) for arg in cmd]

    if not command:
        raise ValueError("Command cannot be empty.")

    if any("\x00" in arg for arg in command):
        raise ValueError(
            "Command contains a null byte."
        )

    return command


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def run(
    cmd: Sequence[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    capture_bytes: int = MAX_CAPTURE_BYTES,
    artifact_name: str | None = None,
    cwd: str | None = None,
) -> RunResult:
    """
    Execute a command and return a structured result.

    Args:
        cmd:
            argv list. NEVER provide a shell command string.

        timeout:
            Maximum execution time in seconds.

        capture_bytes:
            Maximum stdout/stderr kept in memory.

        artifact_name:
            Optional filename for storing command output.

        cwd:
            Optional working directory.

    Returns:
        RunResult containing stdout, stderr, exit code,
        execution duration, and optional artifact path.
    """

    command = _validate_command(cmd)

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    if capture_bytes <= 0:
        raise ValueError(
            "capture_bytes must be greater than 0."
        )

    # Rate-limit command execution.
    _bucket.take()

    run_id = uuid.uuid4().hex[:12]
    started = time.monotonic()

    artifact_path: str | None = None

    # -----------------------------------------------------------------------
    # Artifact path
    # -----------------------------------------------------------------------

    if artifact_name:
        artifact_file = Path(artifact_name)

        # Prevent an absolute path from escaping ARTIFACT_DIR.
        if artifact_file.is_absolute():
            raise ValueError(
                "artifact_name must be a relative path."
            )

        artifact_path_obj = (
            ARTIFACT_DIR / artifact_file
        ).resolve()

        artifact_root = ARTIFACT_DIR.resolve()

        try:
            artifact_path_obj.relative_to(
                artifact_root
            )
        except ValueError as exc:
            raise ValueError(
                "artifact_name must remain inside artifacts/."
            ) from exc

        artifact_path_obj.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        artifact_path = str(
            artifact_path_obj
        )

    # -----------------------------------------------------------------------
    # Execute
    # -----------------------------------------------------------------------

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            shell=False,
            check=False,
        )

        stdout = process.stdout or ""
        stderr = process.stderr or ""
        exit_code = process.returncode

    except subprocess.TimeoutExpired as exc:
        stdout = _decode_output(exc.stdout)
        stderr = _decode_output(exc.stderr)

        stderr += (
            f"\n[TIMEOUT after {timeout}s]"
        )

        exit_code = -9

    except FileNotFoundError as exc:
        duration_ms = int(
            (time.monotonic() - started) * 1000
        )

        result = RunResult(
            command=command,
            stdout="",
            stderr=f"tool not found: {exc}",
            exit_code=127,
            duration_ms=duration_ms,
        )

        _audit(
            {
                "id": run_id,
                "command": command,
            }
        )

        return result

    except PermissionError as exc:
        duration_ms = int(
            (time.monotonic() - started) * 1000
        )

        result = RunResult(
            command=command,
            stdout="",
            stderr=f"permission denied: {exc}",
            exit_code=126,
            duration_ms=duration_ms,
        )

        _audit(
            {
                "id": run_id,
                "command": command,
            }
        )

        return result

    except OSError as exc:
        duration_ms = int(
            (time.monotonic() - started) * 1000
        )

        result = RunResult(
            command=command,
            stdout="",
            stderr=f"OS error: {exc}",
            exit_code=1,
            duration_ms=duration_ms,
        )

        _audit(
            {
                "id": run_id,
                "command": command,
            }
        )

        return result

    # -----------------------------------------------------------------------
    # Capture limits
    # -----------------------------------------------------------------------

    truncated = False

    if len(stdout.encode("utf-8")) > capture_bytes:
        stdout = _truncate_text(
            stdout,
            capture_bytes,
        )
        truncated = True

    if len(stderr.encode("utf-8")) > capture_bytes:
        stderr = _truncate_text(
            stderr,
            capture_bytes,
        )
        truncated = True

    # -----------------------------------------------------------------------
    # Save artifact
    # -----------------------------------------------------------------------

    if artifact_path:
        artifact_content = stdout

        if stderr:
            artifact_content += (
                "\n--- STDERR ---\n"
                + stderr
            )

        Path(artifact_path).write_text(
            artifact_content,
            encoding="utf-8",
        )

    # -----------------------------------------------------------------------
    # Result
    # -----------------------------------------------------------------------

    duration_ms = int(
        (time.monotonic() - started) * 1000
    )

    result = RunResult(
        command=command,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=duration_ms,
        artifact_path=artifact_path,
        truncated=truncated,
    )

    # Audit every completed command.
    _audit(
        {
            "id": run_id,
            "command": command,
        }
    )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_output(value: object) -> str:
    """Safely convert subprocess output to text."""

    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            "replace",
        )

    return str(value)


def _truncate_text(
    text: str,
    max_bytes: int,
) -> str:
    """Truncate UTF-8 text without exceeding max_bytes."""

    encoded = text.encode(
        "utf-8",
        errors="replace",
    )

    if len(encoded) <= max_bytes:
        return text

    truncated = encoded[:max_bytes].decode(
        "utf-8",
        errors="ignore",
    )

    omitted = len(encoded) - len(
        truncated.encode("utf-8")
    )

    return (
        truncated
        + f"\n...[truncated, approximately "
        f"{omitted} bytes omitted]"
    )


# ---------------------------------------------------------------------------
# LLM formatting
# ---------------------------------------------------------------------------

def to_text(result: RunResult) -> str:
    """Format a RunResult for the LLM."""

    command = " ".join(
        shlex.quote(arg)
        for arg in result.command
    )

    header = (
        f"$ {command}\n"
        f"[exit {result.exit_code}, "
        f"{result.duration_ms} ms"
    )

    if result.artifact_path:
        header += (
            f", full output: "
            f"{result.artifact_path}"
        )

    if result.truncated:
        header += ", output truncated"

    header += "]"

    body = result.stdout

    if result.stderr:
        body += (
            "\n--- stderr ---\n"
            + result.stderr
        )

    return header + "\n" + body