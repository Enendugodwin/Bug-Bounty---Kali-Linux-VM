import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import jobs
from src import zap


def _fake_api(component, view, name, params=None):
    key = (component, view, name)
    table = {
        ("core", "view", "version"): {"version": "2.17.0"},
        ("context", "action", "newContext"): {"contextId": "1"},
        ("context", "action", "includeInContext"): {"ok": "true"},
        ("spider", "action", "scan"): {"scan": "0"},
        ("spider", "view", "status"): {"status": "100"},
        ("spider", "view", "results"): {"results": ["https://t/a", "https://t/b"]},
        ("ascan", "action", "scan"): {"scan": "7"},
        ("ascan", "view", "status"): {"status": "100"},
        ("alert", "view", "alerts"): {"alerts": [
            {"alert": "Missing header", "risk": "Low",
             "url": "https://t/", "param": "", "cweid": "693"},
            {"alert": "SQL Injection", "risk": "High",
             "url": "https://t/x?id=1", "param": "id", "cweid": "89"},
        ]},
    }
    return table.get(key, {})


class ZapUnitTests(unittest.TestCase):
    def test_base_url_normalization(self):
        self.assertEqual(zap._base_url("https://www.vinted.com/x?y=1"),
                         "https://www.vinted.com/")
        self.assertEqual(zap._base_url("www.vinted.com"),
                         "https://www.vinted.com/")

    def test_alert_parsing_and_severity(self):
        alerts = zap._parse_alerts({"alerts": [
            {"alert": "a", "risk": "High"},
            {"alert": "b", "risk": "Informational"},
            {"alert": "c", "risk": "Low"},
        ]})
        self.assertEqual([a.severity for a in alerts], ["high", "info", "low"])


class ZapScopeGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = jobs.DB_PATH
        self.old_init = jobs._INITIALIZED_PATH
        jobs.DB_PATH = Path(self.tmp.name) / "zap.sqlite3"
        jobs._INITIALIZED_PATH = None

    def tearDown(self):
        jobs.DB_PATH = self.old_db
        jobs._INITIALIZED_PATH = self.old_init
        self.tmp.cleanup()

    def test_spider_refuses_out_of_scope_without_calling_zap(self):
        with patch.object(zap.scope, "check", return_value=(False, "not listed")), \
             patch.object(zap, "_api") as api:
            report = zap.run_spider("evil.example")
        api.assert_not_called()
        self.assertFalse(report.authorized)
        self.assertIn("not listed", report.to_text())

    def test_spider_reports_unavailable_zap(self):
        def boom(*a, **k):
            raise zap.ZapError("connection refused")
        with patch.object(zap.scope, "check", return_value=(True, "ok")), \
             patch.object(zap, "_api", side_effect=boom):
            report = zap.run_spider("in.example")
        self.assertTrue(report.authorized)
        self.assertFalse(report.available)
        self.assertIn("ZAP unavailable", report.to_text())

    def test_spider_happy_path(self):
        fake = SimpleNamespace(rules={"max_requests_per_second": 3})
        with patch.object(zap.scope, "check", return_value=(True, "ok")), \
             patch.object(zap.scope, "get_scope", return_value=fake), \
             patch.object(zap, "_api", side_effect=_fake_api):
            report = zap.run_spider("in.example", poll=0)
        self.assertTrue(report.available)
        self.assertEqual(report.version, "2.17.0")
        self.assertEqual(report.urls_found, 2)
        self.assertEqual(len(report.alerts), 2)
        self.assertIn("high=1", report.to_text())

    def test_active_scan_requires_confirm(self):
        with patch.object(zap.scope, "check", return_value=(True, "ok")), \
             patch.object(zap, "_api", side_effect=_fake_api):
            report = zap.run_active_scan("in.example", confirm_active=False)
        self.assertIn("confirm_active=true", report.error)

    def test_active_scan_requires_scope_rule(self):
        fake = SimpleNamespace(rules={"allow_active_scan": False})
        with patch.object(zap.scope, "check", return_value=(True, "ok")), \
             patch.object(zap.scope, "get_scope", return_value=fake), \
             patch.object(zap, "_api", side_effect=_fake_api):
            report = zap.run_active_scan("in.example", confirm_active=True)
        self.assertIn("allow_active_scan", report.error)

    def test_active_scan_runs_when_confirmed_and_allowed(self):
        fake = SimpleNamespace(rules={"allow_active_scan": True})
        with patch.object(zap.scope, "check", return_value=(True, "ok")), \
             patch.object(zap.scope, "get_scope", return_value=fake), \
             patch.object(zap, "_api", side_effect=_fake_api):
            report = zap.run_active_scan("in.example", confirm_active=True,
                                         poll=0)
        self.assertIsNone(report.error)
        self.assertEqual(report.scan_id, "7")
        self.assertEqual(len(report.alerts), 2)


if __name__ == "__main__":
    unittest.main()
