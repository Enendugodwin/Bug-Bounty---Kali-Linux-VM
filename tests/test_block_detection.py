"""Tests for WAF/edge block detection and block-page artifact quarantine."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import assess as assess_mod
from src import jobs
from src import waf
from src.findings import Finding, quarantine_waf_artifacts


IMPERVA_BLOCK = (
    "HTTP/1.1 503 Service Unavailable\r\n"
    "Content-Type: text/html\r\n"
    "Cache-Control: no-cache\r\n"
    "X-Iinfo: 52-65206529-0 0NNN RT(1791110938747 1)\r\n"
    "\r\n"
    '<html><head><META NAME="ROBOTS" CONTENT="NOINDEX"></head>'
    '<body><iframe src="/_Incapsula_Resource?CWUDNSAI=27"></iframe>'
    "Request unsuccessful. Incapsula incident ID: 0-225952920898176238"
    "</body></html>"
)

NORMAL_OK = (
    "HTTP/1.1 200 OK\r\n"
    "Server: cloudflare\r\n"
    "CF-RAY: 8b1c2d3e4f5a6b7c\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html><body>Welcome to the application</body></html>"
)


class ClassifyResponseTests(unittest.TestCase):
    def test_imperva_block_page_is_detected(self):
        status, head, body = waf._parse_http_response(IMPERVA_BLOCK)
        verdict = waf.classify_response(status, head, body)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.kind, "block")
        self.assertEqual(verdict.vendor, "Imperva Incapsula")
        self.assertEqual(verdict.status, 503)
        self.assertTrue(verdict.evidence)

    def test_cloudflare_challenge_is_not_a_hard_block(self):
        status, head, body = waf._parse_http_response(
            "HTTP/1.1 503 Service Unavailable\r\nServer: cloudflare\r\n\r\n"
            "<html><title>Just a moment...</title>"
            "checking your browser</html>"
        )
        verdict = waf.classify_response(status, head, body)
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.kind, "challenge")
        self.assertEqual(verdict.vendor, "Cloudflare")

    def test_normal_response_with_waf_header_is_not_blocked(self):
        status, head, body = waf._parse_http_response(NORMAL_OK)
        verdict = waf.classify_response(status, head, body)
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.kind, "")
        self.assertIsNone(verdict.vendor)

    def test_bare_429_is_treated_as_edge_block(self):
        verdict = waf.classify_response(429, "", "")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.kind, "block")


class DetectBlockTests(unittest.TestCase):
    def _fake(self, stdout):
        return SimpleNamespace(command=["curl"], stdout=stdout, stderr="",
                               exit_code=0, duration_ms=1, artifact_path=None)

    def test_detect_block_reports_imperva(self):
        with patch.object(waf.runner, "run",
                          return_value=self._fake(IMPERVA_BLOCK)):
            verdict = waf.detect_block("example.test")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.vendor, "Imperva Incapsula")

    def test_detect_block_passes_normal_site(self):
        with patch.object(waf.runner, "run",
                          return_value=self._fake(NORMAL_OK)):
            verdict = waf.detect_block("example.test")
        self.assertFalse(verdict.blocked)

    def test_detect_block_handles_no_response(self):
        with patch.object(waf.runner, "run",
                          return_value=self._fake("")):
            verdict = waf.detect_block("example.test")
        self.assertFalse(verdict.blocked)
        self.assertTrue(verdict.evidence)


class QuarantineTests(unittest.TestCase):
    def test_block_page_artifact_is_quarantined(self):
        artifact = Finding(
            id="a", title="[999100] Uncommon header(s) 'x-iinfo' found",
            severity="info", target="example.test", tool="nikto",
            endpoint="https://example.test/",
            evidence="[999100] /: Uncommon header(s) 'x-iinfo' found",
        )
        real = Finding(
            id="b", title="Open port 443/tcp", severity="info",
            target="example.test", tool="nmap", endpoint="example.test:443",
            evidence="443/tcp open ssl/https",
        )
        kept, quarantined = quarantine_waf_artifacts([artifact, real])
        self.assertEqual([f.id for f in kept], ["b"])
        self.assertEqual([f.id for f in quarantined], ["a"])


class AssessBlockIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = jobs.DB_PATH
        self.old_init = jobs._INITIALIZED_PATH
        jobs.DB_PATH = Path(self.tmp.name) / "block.sqlite3"
        jobs._INITIALIZED_PATH = None

    def tearDown(self):
        jobs.DB_PATH = self.old_db
        jobs._INITIALIZED_PATH = self.old_init
        self.tmp.cleanup()

    def test_blocked_target_is_inconclusive_and_runs_no_scanners(self):
        fake_scope = SimpleNamespace(
            rules={"allowed_ports": [80, 443], "max_requests_per_second": 3,
                   "max_concurrency": 5, "fetch_exposed_files": False},
            ex_paths=[], program={},
            check=lambda _target: (True, "test scope"),
        )
        blocked = waf.BlockVerdict(blocked=True, kind="block", status=503,
                                   vendor="Imperva Incapsula",
                                   evidence=["Imperva Incapsula: page signature"])
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            return SimpleNamespace(command=argv, stdout="", stderr="",
                                   exit_code=0, duration_ms=1,
                                   artifact_path=None)

        try:
            with patch.object(assess_mod.scope, "get_scope", return_value=fake_scope), \
                 patch.object(assess_mod.waf, "detect_block", return_value=blocked), \
                 patch.object(assess_mod.runner, "run", side_effect=fake_run):
                assessment = assess_mod.run_assessment(
                    "example.test", profile="web",
                    reports_dir=Path(self.tmp.name) / "reports",
                )
            self.assertEqual(assessment.scan_status, "inconclusive")
            self.assertTrue(assessment.block.get("blocked"))
            self.assertEqual(assessment.findings, [])
            self.assertEqual(assessment.commands, [])
            # No scanner (nmap/nikto/gobuster) was invoked.
            self.assertEqual(calls, [])
        finally:
            pass


if __name__ == "__main__":
    unittest.main()
