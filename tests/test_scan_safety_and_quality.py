import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from starlette.testclient import TestClient

from src import jobs
from src import assess as assess_mod
from src import cve as cve_mod
from src.scope import Scope
from src.findings import Finding, dedupe, parse_ffuf_json, parse_gobuster, parse_nmap
from src.matrix import parse_wapiti
from src.cve import parse_nmap_vuln
from src import matrix
from src import webgui


class FindingQualityTests(unittest.TestCase):
    def test_auth_challenge_is_not_reported_as_exposed_resource(self):
        gobuster = parse_gobuster(
            ".env (Status: 401) [Size: 10252]", "example.test",
            "https://example.test",
        )
        ffuf = parse_ffuf_json(json.dumps({"results": [{
            "url": "https://example.test/.env", "status": 403, "length": 10,
        }]}), "example.test")
        self.assertEqual(gobuster[0].severity, "info")
        self.assertEqual(ffuf[0].severity, "info")

    def test_expected_http_ports_are_informational_not_low(self):
        findings = parse_nmap(
            "80/tcp open ssl/http?\n443/tcp open ssl/https?", "example.test"
        )
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.severity == "info" for f in findings))

    def test_cross_tool_exposed_file_is_one_finding_with_sources(self):
        a = Finding(
            id="a", title="Discovered path: .env", severity="high",
            target="example.test", tool="gobuster",
            endpoint="http://example.test/.env", confidence="high",
            evidence="HTTP 200",
        )
        b = Finding(
            id="b", title="Exposed .env file (secrets)", severity="critical",
            target="example.test", tool="nuclei",
            endpoint="https://example.test/.env", confidence="high",
            evidence="Response body redacted",
        )
        merged = dedupe([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "critical")
        self.assertEqual(set(merged[0].sources), {"gobuster", "nuclei"})
        self.assertIn("redacted", merged[0].evidence.lower())

    def test_wapiti_ccs_is_not_auto_critical(self):
        payload = {
            "vulnerabilities": {
                "TLS/SSL misconfigurations": [{
                    "level": 4,
                    "path": "/",
                    "info": "Server is vulnerable to OpenSSL CCS (CVE-2014-0224)",
                    "http_request": "GET /",
                }]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wapiti.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            finding = parse_wapiti(path, "example.test")[0]
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.confidence, "low")
        self.assertEqual(finding.validation_status, "needs_manual_validation")


class ScopePathExclusionTests(unittest.TestCase):
    def test_wildcard_path_exclusions_match_nested_paths(self):
        sc = Scope(
            in_domains=["www.wien.at"],
            ex_paths=["*/agssoe/*", "*/geoserverneuogd/*"],
            rules={"allowed_ports": [80, 443],
                   "allowed_schemes": ["https", "http"]},
        )
        self.assertFalse(sc.check("https://www.wien.at/agssoe/api")[0])
        self.assertFalse(sc.check(
            "https://www.wien.at/service/geoserverneuogd/wms")[0])
        self.assertTrue(sc.check("https://www.wien.at/angebote")[0])

    def test_scope_filtered_wordlist_removes_excluded_paths(self):
        sc = Scope(
            in_domains=["www.wien.at"],
            ex_paths=["*/agssoe/*", "*/geoserverneuogd/*"],
            rules={"allowed_ports": [80, 443],
                   "allowed_schemes": ["https", "http"]},
        )
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "words.txt"
            source.write_text("robots.txt\nagssoe/api\nservice/geoserverneuogd/wms\n",
                              encoding="utf-8")
            old_artifact_dir = assess_mod.runner.ARTIFACT_DIR
            assess_mod.runner.ARTIFACT_DIR = Path(tmp) / "artifacts"
            assess_mod.runner.ARTIFACT_DIR.mkdir()
            temp_file = None
            try:
                filtered, temp_file, removed = assess_mod._scope_filtered_wordlist(
                    str(source), "https://www.wien.at", sc, "vienna", 443, "test"
                )
                words = Path(filtered).read_text(encoding="utf-8").splitlines()
                self.assertEqual(words, ["robots.txt"])
                self.assertEqual(removed, 2)
            finally:
                if temp_file:
                    temp_file.unlink(missing_ok=True)
                assess_mod.runner.ARTIFACT_DIR = old_artifact_dir

    def test_nmap_prose_mention_is_not_a_vulnerability_match(self):
        text = "| This service may be vulnerable to several issues.\n|_ See vendor docs"
        self.assertEqual(parse_nmap_vuln(text, "example.test"), [])

    def test_nmap_explicit_state_is_manual_validation(self):
        text = "|_test-script: State: VULNERABLE\n|   IDs: CVE:CVE-2025-12345"
        findings = parse_nmap_vuln(text, "example.test")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].validation_status, "needs_manual_validation")


class PersistentJobTests(unittest.TestCase):
    def test_job_and_steps_survive_registry_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_path = jobs.DB_PATH
            jobs.DB_PATH = Path(tmp) / "jobs.sqlite3"
            try:
                jid = jobs.create_job("matrix", "example.test", source="test")
                jobs.record_event(jid, {"type": "scan_start"})
                jobs.record_event(jid, {"type": "plan", "steps": [
                    {"key": "nmap", "label": "nmap", "agent": "Recon Agent", "timeout": 30},
                ]})
                jobs.record_event(jid, {"type": "step_start", "key": "nmap",
                                        "label": "nmap", "agent": "Recon Agent",
                                        "timeout": 30})
                snapshot = jobs.get_job(jid)
                self.assertEqual(snapshot["status"], "running")
                self.assertEqual(snapshot["steps"][0]["status"], "running")
                jobs.record_event(jid, {"type": "step_end", "key": "nmap",
                                        "label": "nmap", "agent": "Recon Agent",
                                        "status": "done", "exit_code": 0,
                                        "duration_ms": 25, "findings": 2})
                # A later plan update must not reset an already-finished step.
                jobs.record_event(jid, {"type": "plan", "steps": [
                    {"key": "nmap", "label": "nmap", "agent": "Recon Agent", "timeout": 30},
                    {"key": "nikto", "label": "nikto", "agent": "Web Agent", "timeout": 30},
                ]})
                snapshot = jobs.get_job(jid)
                self.assertEqual(snapshot["steps"][0]["status"], "done")
                self.assertEqual(snapshot["steps"][0]["findings"], 2)
                self.assertEqual(snapshot["steps"][1]["status"], "pending")
                self.assertEqual(jobs.list_jobs(limit=5)[0]["id"], jid)
            finally:
                jobs.DB_PATH = old_path

    def test_gui_api_reads_jobs_not_only_its_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_path = jobs.DB_PATH
            old_init_path = jobs._INITIALIZED_PATH
            jobs.DB_PATH = Path(tmp) / "gui-jobs.sqlite3"
            jobs._INITIALIZED_PATH = None
            try:
                jid = jobs.create_job("matrix", "example.test", source="cli",
                                      agent="Matrix Agent")
                jobs.record_event(jid, {"type": "scan_start"})
                jobs.record_event(jid, {"type": "plan", "steps": [
                    {"key": "nmap", "label": "nmap", "agent": "Recon Agent"},
                ]})
                with TestClient(webgui.app) as client:
                    listing = client.get("/api/scans").json()["scans"]
                    self.assertEqual(listing[0]["id"], jid)
                    self.assertEqual(listing[0]["status"], "running")
                    detail = client.get(f"/api/scan/{jid}").json()
                    self.assertEqual(detail["steps"][0]["agent"], "Recon Agent")
            finally:
                jobs.DB_PATH = old_path
                jobs._INITIALIZED_PATH = old_init_path

    def test_network_dry_run_obeys_scope_rate_and_port_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_path = jobs.DB_PATH
            old_init = jobs._INITIALIZED_PATH
            jobs.DB_PATH = Path(tmp) / "dry-run.sqlite3"
            jobs._INITIALIZED_PATH = None
            fake_scope = SimpleNamespace(
                rules={"allowed_ports": [80, 443],
                       "max_requests_per_second": 3,
                       "max_concurrency": 5, "fetch_exposed_files": False},
                program={}, check=lambda _target: (True, "test scope"),
            )
            try:
                with patch.object(assess_mod.scope, "get_scope", return_value=fake_scope):
                    assessment = assess_mod.run_assessment(
                        "www.wien.at", profile="network", dry_run=True,
                        write_report=False,
                    )
                command = assessment.commands[0]["command"]
                self.assertIn("--max-rate 3", command)
                self.assertIn("-p 80,443", command)
            finally:
                jobs.DB_PATH = old_path
                jobs._INITIALIZED_PATH = old_init

    def test_assessment_orchestrator_persists_completed_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_path = jobs.DB_PATH
            old_init_path = jobs._INITIALIZED_PATH
            jobs.DB_PATH = Path(tmp) / "assess-jobs.sqlite3"
            jobs._INITIALIZED_PATH = None
            fake_scope = SimpleNamespace(
                rules={"allowed_ports": [80], "max_requests_per_second": 1,
                       "max_concurrency": 1, "fetch_exposed_files": False},
                ex_paths=[],
                program={}, check=lambda _target: (True, "test scope"),
            )

            def fake_run(argv, **kwargs):
                output = "80/tcp open http\n" if argv[0] == "nmap" else ""
                return SimpleNamespace(
                    command=argv, stdout=output, stderr="", exit_code=0,
                    duration_ms=1, artifact_path=None,
                )

            try:
                with patch.object(assess_mod.scope, "get_scope", return_value=fake_scope), \
                     patch.object(assess_mod, "_probe_catchall", return_value=(404, None)), \
                     patch.object(assess_mod.runner, "run", side_effect=fake_run), \
                     patch.object(assess_mod.memory.memory, "add_document", return_value=None):
                    assessment = assess_mod.run_assessment(
                        "example.test", profile="web", operator="unit-test",
                        reports_dir=Path(tmp) / "reports",
                    )
                saved = jobs.get_job(assessment.job_id)
                self.assertEqual(saved["status"], "done")
                self.assertEqual(len(saved["steps"]), 4)
                self.assertTrue(all(s["status"] == "done" for s in saved["steps"]))
            finally:
                jobs.DB_PATH = old_path
                jobs._INITIALIZED_PATH = old_init_path


class IntrusiveGateTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_path = jobs.DB_PATH
        jobs.DB_PATH = Path(self.temp_dir.name) / "gates.sqlite3"

    def tearDown(self):
        jobs.DB_PATH = self.old_path
        self.temp_dir.cleanup()

    def test_sqlmap_requires_explicit_confirmation_and_scope_rule(self):
        fake_scope = SimpleNamespace(
            rules={"allow_intrusive": True}, program={},
            check=lambda _target: (True, "authorized"),
        )
        with patch.object(matrix.scope, "get_scope", return_value=fake_scope):
            with self.assertRaises(PermissionError):
                matrix.run_matrix("example.test", include_intrusive=True,
                                  confirm_intrusive=False)

    def test_sqlmap_also_requires_scope_authorization(self):
        fake_scope = SimpleNamespace(
            rules={"allow_intrusive": False}, program={},
            check=lambda _target: (True, "authorized"),
        )
        with patch.object(matrix.scope, "get_scope", return_value=fake_scope):
            with self.assertRaises(PermissionError):
                matrix.run_matrix("example.test", include_intrusive=True,
                                  confirm_intrusive=True)


class CveScopeLimitTests(unittest.TestCase):
    def test_cve_scan_clamps_nuclei_and_redacts_saved_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_db = jobs.DB_PATH
            old_init = jobs._INITIALIZED_PATH
            old_artifacts = cve_mod.runner.ARTIFACT_DIR
            jobs.DB_PATH = root / "jobs.sqlite3"
            jobs._INITIALIZED_PATH = None
            cve_mod.runner.ARTIFACT_DIR = root / "artifacts"
            fake_scope = SimpleNamespace(
                rules={"max_requests_per_second": 3, "max_concurrency": 5,
                       "allowed_ports": [80, 443],
                       "allowed_schemes": ["https", "http"],
                       "allow_intrusive": False},
                program={}, check=lambda _target: (True, "test scope"),
            )
            secret = "super-secret-test-value"
            scanner_line = json.dumps({
                "template-id": "generic-env",
                "info": {"name": "env disclosure", "severity": "high",
                         "classification": {}},
                "matched-at": "https://example.test/.env",
                "response": f"SECRET_KEY={secret}",
                "curl-command": "curl https://example.test/.env",
            })

            def fake_run(argv, **kwargs):
                return SimpleNamespace(stdout=scanner_line, stderr="", exit_code=0,
                                       duration_ms=1, artifact_path=None)

            try:
                with patch.object(cve_mod.scope, "get_scope", return_value=fake_scope), \
                     patch.object(cve_mod.runner, "run", side_effect=fake_run), \
                     patch.object(cve_mod.memory.memory, "add_document", return_value=None):
                    assessment = cve_mod.run_cve_scan(
                        "example.test", rate=20, concurrency=10, latest=0,
                        run_latest=False, run_severity=True, nmap_vuln=False,
                        reports_dir=root / "reports",
                    )
                cmd = assessment.commands[0]["command"]
                self.assertIn("-rate-limit 3", cmd)
                self.assertIn("-concurrency 5", cmd)
                self.assertIn("https://example.test", cmd)
                self.assertIn("http://example.test", cmd)
                artifact = Path(assessment.artifacts[0]).read_text(encoding="utf-8")
                self.assertNotIn(secret, artifact)
                self.assertIn("REDACTED", artifact)
            finally:
                jobs.DB_PATH = old_db
                jobs._INITIALIZED_PATH = old_init
                cve_mod.runner.ARTIFACT_DIR = old_artifacts


if __name__ == "__main__":
    unittest.main()
