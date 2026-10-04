"""CVE intelligence enrichment: CVSS (scanner / NVD) and EPSS.

Non-intrusive: this module talks **only** to public intelligence APIs
(FIRST.org EPSS and the NVD), never to the scanned target. Results are cached
on disk so repeat runs are offline and polite, and any network failure is
swallowed — enrichment is best-effort and must never break a scan.

Sources
-------
* EPSS  — https://api.first.org/data/v1/epss        (public, batch by CVE)
* NVD   — https://services.nvd.nist.gov/rest/json/cves/2.0
          (rate-limited; set ``NVD_API_KEY`` for a higher quota, or
          ``KPM_NVD_ANON=1`` to allow a few anonymous lookups)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.request
from pathlib import Path

log = logging.getLogger("kpm.cveintel")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_PATH = Path(os.getenv("KPM_CVEINTEL_CACHE",
                            PROJECT_ROOT / "logs" / "cveintel.json"))
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = int(os.getenv("KPM_CVEINTEL_TIMEOUT", "12"))
EPSS_CHUNK = 100

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.I)


def _http_json(url: str, *, headers: dict | None = None,
               timeout: int = TIMEOUT) -> dict:
    req = urllib.request.Request(
        url, headers=headers or {"User-Agent": "KaliPentestMCP/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _load_cache(path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("epss", {})
            data.setdefault("nvd", {})
            return data
    except Exception:  # noqa: BLE001 - missing/corrupt cache is fine
        pass
    return {"epss": {}, "nvd": {}}


def _save_cache(path, cache: dict) -> None:
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache), encoding="utf-8")
        tmp.replace(p)
    except Exception as exc:  # noqa: BLE001
        log.debug("cveintel cache save failed: %s", exc)


# ---------------------------------------------------------------------------
# Extraction / lookups
# ---------------------------------------------------------------------------

def cves_of(f) -> list[str]:
    """All CVE ids referenced by a finding (structured or free text)."""
    found = [str(c).upper() for c in (getattr(f, "cves", None) or []) if c]
    text = f"{f.title} {f.description} {' '.join(f.references or [])}"
    for match in _CVE_RE.findall(text):
        cve = match.upper()
        if cve not in found:
            found.append(cve)
    return found


def _epss_lookup(cves: list[str], cache: dict, *, online: bool) -> None:
    missing = [c for c in cves if c not in cache["epss"]]
    if not missing or not online:
        return
    for start in range(0, len(missing), EPSS_CHUNK):
        chunk = missing[start:start + EPSS_CHUNK]
        url = EPSS_URL + "?cve=" + ",".join(chunk)
        try:
            data = _http_json(url)
        except Exception as exc:  # noqa: BLE001
            log.debug("EPSS lookup failed: %s", exc)
            continue
        for row in (data.get("data") or []):
            cve = str(row.get("cve", "")).upper()
            if not cve:
                continue
            try:
                cache["epss"][cve] = {
                    "epss": float(row.get("epss")),
                    "percentile": float(row.get("percentile")),
                    "date": row.get("date", ""),
                }
            except (TypeError, ValueError):
                continue


def _nvd_extract(payload: dict) -> tuple[float | None, str, list[str]]:
    """Return ``(baseScore, vector, cwes)`` from an NVD 2.0 response."""
    try:
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return None, "", []
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {}) or {}
        cvss: float | None = None
        vector = ""
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                    "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                cvss = data.get("baseScore")
                vector = data.get("vectorString", "") or ""
                break
        cwes: list[str] = []
        for weakness in (cve.get("weaknesses") or []):
            for desc in (weakness.get("description") or []):
                value = desc.get("value")
                if value and value.lower() != "nvd-cwe-noinfo" and value not in cwes:
                    cwes.append(value)
        return cvss, vector, cwes
    except Exception:  # noqa: BLE001
        return None, "", []


def _nvd_lookup(cves: list[str], cache: dict, *, key: str, online: bool,
                max_nvd: int) -> None:
    pending = [c for c in cves if c not in cache["nvd"]]
    if not pending or not online:
        return
    anon_ok = os.getenv("KPM_NVD_ANON", "") == "1"
    if not key and not anon_ok:
        return
    spacing = 0.7 if key else 6.1
    cap = max_nvd if key else min(max_nvd, 5)
    headers = {"User-Agent": "KaliPentestMCP/1.0"}
    if key:
        headers["apiKey"] = key
    for cve in pending[:cap]:
        url = NVD_URL + "?cveId=" + cve
        try:
            payload = _http_json(url, headers=headers)
        except Exception as exc:  # noqa: BLE001
            log.debug("NVD lookup failed for %s: %s", cve, exc)
            continue
        cvss, vector, cwes = _nvd_extract(payload)
        cache["nvd"][cve] = {"cvss": cvss, "vector": vector, "cwe": cwes}
        time.sleep(spacing)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich(findings: list, *, online: bool = True, cache_path=None,
           nvd_key: str | None = None, max_nvd: int = 25) -> dict:
    """Annotate *findings* in place with CVSS and EPSS scores.

    CVSS prefers a score the scanner already supplied (e.g. nuclei) and is
    topped up from the NVD when a key (or ``KPM_NVD_ANON``) is available.
    EPSS is always fetched from FIRST.org (batched) for any CVEs found.
    """
    cache = _load_cache(cache_path or CACHE_PATH)

    all_cves: list[str] = []
    for f in findings:
        for cve in cves_of(f):
            if cve not in all_cves:
                all_cves.append(cve)

    nvd_key = nvd_key if nvd_key is not None else os.getenv("NVD_API_KEY", "")
    _epss_lookup(all_cves, cache, online=online)
    _nvd_lookup(all_cves, cache, key=nvd_key, online=online, max_nvd=max_nvd)
    _save_cache(cache_path or CACHE_PATH, cache)

    epss_hits = cvss_hits = 0
    for f in findings:
        cves = cves_of(f)
        if not cves:
            continue
        for cve in cves:
            entry = cache["nvd"].get(cve) or {}
            score = entry.get("cvss")
            if score is not None and (f.cvss is None or float(score) > f.cvss):
                f.cvss = float(score)
                f.cvss_vector = entry.get("vector", "") or f.cvss_vector
            for cwe in (entry.get("cwe") or []):
                if cwe and cwe not in f.cwe_ids:
                    f.cwe_ids.append(cwe)
        if f.cvss is not None:
            cvss_hits += 1
        best = None
        for cve in cves:
            row = cache["epss"].get(cve)
            if row and (best is None or row.get("epss", 0) > best.get("epss", 0)):
                best = row
        if best:
            f.epss = best.get("epss")
            f.epss_percentile = best.get("percentile")
            epss_hits += 1

    if all_cves:
        log.info("cveintel: %d CVE(s), %d CVSS, %d EPSS annotated",
                 len(all_cves), cvss_hits, epss_hits)
    return {"cves": len(all_cves), "cvss": cvss_hits, "epss": epss_hits}


def enrich_assessment(assessment, **kwargs) -> dict:
    """Best-effort ``enrich`` for an :class:`Assessment`; never raises."""
    try:
        return enrich(assessment.findings, **kwargs)
    except Exception as exc:  # noqa: BLE001
        log.debug("cveintel enrichment failed: %s", exc)
        return {}
