"""Authorization / scope enforcement for bug-bounty assessments.

Design goals
------------
* **Deny-by-default**: a target must be explicitly listed in scope and must
  not match any exclusion.
* **Rich, program-aware scope**: ``scope.yaml`` describes in-scope
  domains/wildcards/IPs/CIDRs, out-of-scope exclusions, paths, allowed
  ports/schemes and rules of engagement.
* **Legacy compatible**: if ``scope.yaml`` is absent the original flat
  ``scope.txt`` is still honoured.

Every assessment entry point MUST call :func:`assert_allowed` (or check
:func:`is_in_scope`) before invoking any external tool.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCOPE_YAML = Path(os.getenv("KPM_SCOPE_FILE", PROJECT_ROOT / "scope.yaml")).expanduser()
SCOPE_TXT = Path(os.getenv("KPM_SCOPE_TXT", PROJECT_ROOT / "scope.txt")).expanduser()

log = logging.getLogger("kpm.scope")


class ScopeError(Exception):
    """Raised when a target is not authorized by the active scope."""


# ---------------------------------------------------------------------------
# Target parsing helpers
# ---------------------------------------------------------------------------

def normalize_host(target: str) -> str:
    """Return a bare lowercase hostname/IP from a target string.

    Accepts ``host``, ``host:port``, ``scheme://host:port/path`` and
    IPv6 literals such as ``[::1]:443``.
    """
    t = (target or "").strip()
    if not t:
        return ""

    if "://" in t:
        host = urlparse(t).hostname or ""
    else:
        host = t.split("/", 1)[0]

    if "@" in host:
        host = host.rsplit("@", 1)[1]

    if host.startswith("["):  # IPv6 literal
        end = host.find("]")
        if end != -1:
            host = host[1:end]
        return host.lower()

    # Strip a single trailing :port (hostnames / IPv4).
    if host.count(":") == 1:
        host = host.split(":", 1)[0]

    return host.lower().rstrip(".")


def extract_path(target: str) -> str:
    """Return the URL path component of a target (default ``/``)."""
    t = (target or "").strip()
    if "://" in t:
        parsed = urlparse(t)
        return parsed.path or "/"
    if "/" in t:
        return "/" + t.split("/", 1)[1]
    return "/"


def extract_port(target: str) -> int | None:
    """Return an explicit port from a target, if present."""
    t = (target or "").strip()
    if "://" in t:
        try:
            return urlparse(t).port
        except ValueError:
            return None
    hostport = t.split("/", 1)[0]
    if hostport.startswith("["):  # [::1]:80
        end = hostport.find("]")
        if end != -1 and hostport[end + 1:end + 2] == ":":
            tail = hostport[end + 2:]
            return int(tail) if tail.isdigit() else None
        return None
    if hostport.count(":") == 1:
        _, _, port = hostport.partition(":")
        return int(port) if port.isdigit() else None
    return None


def extract_scheme(target: str) -> str | None:
    t = (target or "").strip()
    if "://" in t:
        return urlparse(t).scheme.lower()
    return None


def _as_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _match_wildcard(host: str, suffix: str, include_apex: bool = False) -> bool:
    suffix = suffix.lower().strip().lstrip("*.")
    if not suffix:
        return False
    if host == suffix:
        return include_apex
    return host.endswith("." + suffix)


# ---------------------------------------------------------------------------
# Scope model
# ---------------------------------------------------------------------------

@dataclass
class Scope:
    source: str = "none"
    program: dict = field(default_factory=dict)
    rules: dict = field(default_factory=dict)

    in_domains: list[str] = field(default_factory=list)
    in_wildcards: list[str] = field(default_factory=list)
    in_ips: list[str] = field(default_factory=list)
    in_cidrs: list = field(default_factory=list)

    ex_domains: list[str] = field(default_factory=list)
    ex_wildcards: list[str] = field(default_factory=list)
    ex_ips: list[str] = field(default_factory=list)
    ex_cidrs: list = field(default_factory=list)
    ex_paths: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def entries(self) -> list[str]:
        """Flat list of authorized entries (for display / audit)."""
        out = []
        out += [f"domain:{d}" for d in self.in_domains]
        out += [f"wildcard:{w}" for w in self.in_wildcards]
        out += [f"ip:{i}" for i in self.in_ips]
        out += [f"cidr:{c}" for c in self.in_cidrs]
        return out

    def is_empty(self) -> bool:
        return not (self.in_domains or self.in_wildcards
                    or self.in_ips or self.in_cidrs)

    # ------------------------------------------------------------------
    # Core decision
    # ------------------------------------------------------------------
    def check(
        self,
        target: str,
        *,
        port: int | None = None,
        path: str | None = None,
        scheme: str | None = None,
    ) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` for a target. Deny-by-default."""
        host = normalize_host(target)
        if not host:
            return False, "empty or unparseable target"

        check_path = path if path is not None else extract_path(target)
        check_port = port if port is not None else extract_port(target)
        check_scheme = (scheme or extract_scheme(target) or "").lower() or None

        if self.is_empty():
            return False, "scope is empty (no authorized targets configured)"

        is_ip = False
        ip = None
        try:
            ip = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        # --- Exclusions always win -------------------------------------
        if is_ip:
            for cidr in self.ex_cidrs:
                if ip in cidr:
                    return False, f"{host} is inside excluded network {cidr}"
            if host in self.ex_ips:
                return False, f"{host} is explicitly excluded"
        else:
            if host in self.ex_domains:
                return False, f"{host} is explicitly excluded"
            for w in self.ex_wildcards:
                if _match_wildcard(host, w, include_apex=True):
                    return False, f"{host} matches excluded wildcard {w}"

        for xp in self.ex_paths:
            if "*" in xp and fnmatch.fnmatchcase(check_path, xp):
                return False, f"path {check_path} matches excluded path pattern {xp}"
            base = xp.rstrip("/")
            if ("*" not in xp and base
                    and (check_path == base or check_path.startswith(base + "/"))):
                return False, f"path {check_path} is excluded ({xp})"

        # --- Rules of engagement ---------------------------------------
        allowed_schemes = self.rules.get("allowed_schemes") or []
        if check_scheme and allowed_schemes and check_scheme not in allowed_schemes:
            return False, f"scheme '{check_scheme}' not permitted by rules"

        allowed_ports = self.rules.get("allowed_ports") or []
        if check_port and allowed_ports and int(check_port) not in [
            int(p) for p in allowed_ports
        ]:
            return False, f"port {check_port} not permitted by rules"

        # --- In-scope --------------------------------------------------
        if is_ip:
            if host in self.in_ips:
                return True, f"{host} authorized (ip)"
            for cidr in self.in_cidrs:
                if ip in cidr:
                    return True, f"{host} authorized (in {cidr})"
            return False, f"{host} is not listed in scope"

        if host in self.in_domains:
            return True, f"{host} authorized (domain)"
        for w in self.in_wildcards:
            if _match_wildcard(host, w):
                return True, f"{host} authorized (wildcard {w})"
        return False, f"{host} is not listed in scope"

    def check_network(self, target: str) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` for a CIDR network. Deny-by-default."""
        try:
            net = ipaddress.ip_network(str(target).strip(), strict=False)
        except ValueError:
            return False, f"{target} is not a valid network"
        if self.is_empty():
            return False, "scope is empty (no authorized targets configured)"
        for excluded in self.ex_cidrs:
            if net.overlaps(excluded):
                return False, f"{net} overlaps excluded network {excluded}"
        for cidr in self.in_cidrs:
            if net.subnet_of(cidr):
                return True, f"{net} authorized (in {cidr})"
        for cidr in self.in_cidrs:
            if net.overlaps(cidr):
                return False, (f"{net} is only partially within in-scope {cidr}; "
                               "list tighter networks")
        return False, f"{net} is not within any in-scope cidr"


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> Scope:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise ScopeError(
            "PyYAML is required to read scope.yaml. "
            "Install with: pip install PyYAML"
        ) from exc

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    ins = data.get("in_scope") or {}
    outs = data.get("out_of_scope") or {}

    def _strs(value) -> list[str]:
        return [str(x).strip() for x in (value or []) if str(x).strip()]

    def _nets(value) -> list:
        return [n for n in (_as_network(s) for s in _strs(value)) if n]

    return Scope(
        source=str(path),
        program=data.get("program") or {},
        rules=data.get("rules") or {},
        in_domains=[d.lower().rstrip(".") for d in _strs(ins.get("domains"))],
        in_wildcards=_strs(ins.get("wildcards")),
        in_ips=_strs(ins.get("ips")),
        in_cidrs=_nets(ins.get("cidrs")),
        ex_domains=[d.lower().rstrip(".") for d in _strs(outs.get("domains"))],
        ex_wildcards=_strs(outs.get("wildcards")),
        ex_ips=_strs(outs.get("ips")),
        ex_cidrs=_nets(outs.get("cidrs")),
        ex_paths=_strs(outs.get("paths")),
    )


def _load_txt(path: Path) -> Scope:
    """Legacy flat scope: one entry per line (domain, wildcard, IP, CIDR)."""
    scope = Scope(source=str(path))
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "*" in line:
            scope.in_wildcards.append(line)
            continue
        net = _as_network(line)
        if net is not None and "/" in line:
            scope.in_cidrs.append(net)
            continue
        try:
            ipaddress.ip_address(line)
            scope.in_ips.append(line)
            continue
        except ValueError:
            scope.in_domains.append(line.lower().rstrip("."))
    return scope


def load_scope() -> Scope:
    """Load the authoritative scope, preferring scope.yaml."""
    if SCOPE_YAML.exists():
        return _load_yaml(SCOPE_YAML)
    if SCOPE_TXT.exists():
        return _load_txt(SCOPE_TXT)
    return Scope(source="none")


# ---------------------------------------------------------------------------
# Cached accessors
# ---------------------------------------------------------------------------

_cache: Scope | None = None
_cache_mtime: float = -1.0


def get_scope(force: bool = False) -> Scope:
    """Return the active scope, reloading when the source file changes."""
    global _cache, _cache_mtime
    path = SCOPE_YAML if SCOPE_YAML.exists() else SCOPE_TXT
    mtime = path.stat().st_mtime if path.exists() else 0.0
    if force or _cache is None or mtime != _cache_mtime:
        _cache = load_scope()
        _cache_mtime = mtime
        log.info("Loaded scope from %s (%d entries)",
                 _cache.source, len(_cache.entries()))
    return _cache


def is_in_scope(target: str) -> bool:
    """Backwards-compatible boolean scope check."""
    return get_scope().check(target)[0]


def check(target: str, **kwargs) -> tuple[bool, str]:
    return get_scope().check(target, **kwargs)


def assert_allowed(target: str, **kwargs) -> Scope:
    """Raise :class:`ScopeError` unless *target* is authorized."""
    scope = get_scope()
    ok, reason = scope.check(target, **kwargs)
    if not ok:
        raise ScopeError(f"Target not authorized: {target} ({reason})")
    return scope


def check_network(target: str) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a CIDR network."""
    return get_scope().check_network(target)


def assert_network_allowed(target: str) -> Scope:
    """Raise :class:`ScopeError` unless the CIDR *target* is authorized."""
    scope = get_scope()
    ok, reason = scope.check_network(target)
    if not ok:
        raise ScopeError(f"Network not authorized: {target} ({reason})")
    return scope
