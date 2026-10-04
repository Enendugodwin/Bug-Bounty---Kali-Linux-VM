import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import jobs
from src import waf


class WafUnitTests(unittest.TestCase):
    def test_vendor_signatures_detected(self):
        blob = "Server: cloudflare\nCF-RAY: 8\nSet-Cookie: incap_ses_123"
        vendors = waf._match_vendors(blob)
        self.assertIn("Cloudflare", vendors)
        self.assertIn("Imperva Incapsula", vendors)

    def test_wafw00f_json_is_parsed(self):
        out = '[{"detected": true, "firewall": "Cloudflare"}]'
        self.assertEqual(waf._parse_wafw00f(out), ["Cloudflare"])

    def test_hostname_and_base_url(self):
        self.assertEqual(waf._hostname("https://a.example/x?y=1"), "a.example")
        self.assertEqual(waf._base_url("a.example"), "http://a.example")


class WafScopeGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = jobs.DB_PATH
        self.old_init = jobs._INITIALIZED_PATH
        jobs.DB_PATH = Path(self.tmp.name) / "waf.sqlite3"
        jobs._INITIALIZED_PATH = None

    def tearDown(self):
        jobs.DB_PATH = self.old_db
        jobs._INITIALIZED_PATH = self.old_init
        self.tmp.cleanup()

    def test_out_of_scope_target_is_refused_without_scanning(self):
        with patch.object(waf.scope, "check", return_value=(False, "not listed")):
            report = waf.run_waf_check("evil.example")
        self.assertFalse(report.authorized)
        self.assertEqual(report.origins, [])
        self.assertIn("not listed", report.scope_reason)

    def test_origin_ip_only_probed_when_ip_in_scope(self):
        fake_scope = SimpleNamespace(
            rules={"allowed_ports": [80, 443],
                   "allowed_schemes": ["https", "http"]},
        )

        def check(target, **kwargs):
            if target == "in.example":
                return True, "domain authorized"
            return False, "ip not listed in scope"

        with patch.object(waf.scope, "get_scope", return_value=fake_scope), \
             patch.object(waf.scope, "check", side_effect=check), \
             patch.object(waf, "detect_waf",
                          return_value=waf.Detection(present=True,
                                                     vendors=["Cloudflare"])), \
             patch.object(waf, "resolve_host", return_value=["203.0.113.9"]), \
             patch.object(waf, "probe_origin") as probe:
            report = waf.run_waf_check("in.example")

        probe.assert_not_called()
        self.assertEqual(len(report.origins), 1)
        self.assertFalse(report.origins[0].in_scope)

    def test_no_waf_and_reachable_origin_are_flagged(self):
        fake_scope = SimpleNamespace(rules={})

        def fake_probe(host, ip, **kwargs):
            return waf.OriginProbe(ip=ip, in_scope=True, tested=True,
                                   reachable=True, status=200, bypass_likely=True)

        with patch.object(waf.scope, "get_scope", return_value=fake_scope), \
             patch.object(waf.scope, "check", return_value=(True, "authorized")), \
             patch.object(waf, "detect_waf",
                          return_value=waf.Detection(present=False)), \
             patch.object(waf, "resolve_host", return_value=["203.0.113.9"]), \
             patch.object(waf, "probe_origin", side_effect=fake_probe):
            report = waf.run_waf_check("in.example")

        joined = " ".join(report.flags)
        self.assertIn("NO WAF IN PLACE", joined)
        self.assertIn("ORIGIN IP REACHABLE", joined)


if __name__ == "__main__":
    unittest.main()
