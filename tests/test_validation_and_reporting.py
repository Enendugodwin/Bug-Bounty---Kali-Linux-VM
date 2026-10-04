"""Tests for the item-3 validation pass, CWE mapping and reporting additions."""

import unittest
from unittest.mock import patch

from src import assess as assess_mod
from src.findings import (Finding, cwe_for, drop_noise, is_noise_finding,
                          validation_counts)
from src.report import Assessment, render_markdown


def _finding(**kw):
    base = dict(id="id", title="t", severity="info", target="example.test",
                tool="gobuster", endpoint="https://example.test/.env")
    base.update(kw)
    return Finding(**base)


class CweTests(unittest.TestCase):
    def test_sensitive_file_maps_to_cwe_538(self):
        f = _finding(title="Exposed .env file (secrets)")
        self.assertIn("CWE-538", cwe_for(f))

    def test_directory_listing_maps_to_cwe_548(self):
        f = _finding(title="Directory listing enabled")
        self.assertIn("CWE-548", cwe_for(f))

    def test_generic_finding_has_no_cwe(self):
        f = _finding(title="Open port 443/tcp", description="standard web")
        self.assertEqual(cwe_for(f), "")


class NoiseTests(unittest.TestCase):
    def test_nikto_info_noise_is_dropped(self):
        noise = _finding(title="[740000] Multiple index files found (all unique)",
                         tool="nikto", severity="info")
        real = _finding(title="Open port 443/tcp", tool="nmap", severity="info")
        self.assertTrue(is_noise_finding(noise))
        kept, dropped = drop_noise([noise, real])
        self.assertEqual([f.title for f in kept], ["Open port 443/tcp"])
        self.assertEqual(len(dropped), 1)

    def test_low_severity_is_not_treated_as_noise(self):
        f = _finding(title="Multiple index files found", severity="low")
        self.assertFalse(is_noise_finding(f))


class ValidationPassTests(unittest.TestCase):
    def test_cross_tool_corroboration_upgrades_status(self):
        f = _finding(validation_status="unverified",
                     sources=["gobuster", "feroxbuster"])
        with patch.object(assess_mod, "_http_get") as get:
            assess_mod.validate_findings([f])
        self.assertEqual(f.validation_status, "scanner_match")
        get.assert_not_called()

    def test_failed_recheck_marks_unconfirmed(self):
        f = _finding(title="Discovered path: /.env", severity="high",
                     tool="gobuster", confidence="high",
                     evidence=".env (Status: 200) [Size: 10]",
                     validation_status="unverified")
        with patch.object(assess_mod.scope, "check", return_value=(True, "test")), \
             patch.object(assess_mod, "_http_get", return_value=(404, "", "")):
            assess_mod.validate_findings([f])
        self.assertEqual(f.validation_status, "unconfirmed")
        self.assertEqual(f.confidence, "low")
        self.assertIn("false positive", f.description.lower())

    def test_successful_recheck_confirms(self):
        f = _finding(title="Discovered path: /robots.txt", severity="low",
                     tool="gobuster", confidence="high",
                     evidence="robots.txt (Status: 200) [Size: 42]",
                     validation_status="unverified")
        with patch.object(assess_mod.scope, "check", return_value=(True, "test")), \
             patch.object(assess_mod, "_http_get", return_value=(200, "text/plain", "ok")):
            assess_mod.validate_findings([f])
        self.assertEqual(f.validation_status, "confirmed")

    def test_already_confirmed_is_not_refetched(self):
        f = _finding(title="Discovered path: /a", severity="low",
                     tool="gobuster", confidence="high",
                     evidence="a (Status: 200) [Size: 3]",
                     validation_status="confirmed")
        with patch.object(assess_mod, "_http_get") as get:
            assess_mod.validate_findings([f])
        get.assert_not_called()


class ReportingTests(unittest.TestCase):
    def test_report_has_validation_summary_cwe_and_unverified_section(self):
        f = _finding(title="Exposed .env file (secrets)", severity="critical",
                     tool="gobuster", confidence="high",
                     description="Publicly readable resource.",
                     validation_status="needs_manual_validation",
                     endpoint="https://example.test/.env")
        a = Assessment(target="example.test", authorized=True,
                       scope_reason="test", scan_status="complete", findings=[f])
        md = render_markdown(a)
        self.assertIn("Confidence & Validation", md)
        self.assertIn("CWE-538", md)
        self.assertIn("Needs Manual Validation", md)
        self.assertEqual(validation_counts([f])["needs_manual_validation"], 1)

    def test_report_shows_cvss_epss_and_top_risk(self):
        f = _finding(title="CVE-2021-44228 log4shell", severity="critical",
                     endpoint="https://example.test/x",
                     cvss=10.0, cvss_vector="CVSS:3.1/AV:N",
                     epss=0.97, epss_percentile=0.999,
                     cves=["CVE-2021-44228"])
        a = Assessment(target="example.test", authorized=True,
                       scope_reason="test", scan_status="complete", findings=[f])
        md = render_markdown(a)
        self.assertIn("Top Risk (by EPSS)", md)
        self.assertIn("CVSS 10", md)
        self.assertIn("EPSS 0.970", md)


if __name__ == "__main__":
    unittest.main()
