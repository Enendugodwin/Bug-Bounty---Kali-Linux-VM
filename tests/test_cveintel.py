"""Tests for CVSS/EPSS enrichment (offline, mocked HTTP)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import cveintel
from src import cve as cve_mod
from src.findings import Finding


def _finding(**kw):
    base = dict(id="id", title="finding", severity="high", target="example.test",
                tool="nuclei", endpoint="https://example.test/x")
    base.update(kw)
    return Finding(**base)


EPSS_PAYLOAD = {"status": "OK", "data": [
    {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.999",
     "date": "2026-10-04"},
]}
NVD_PAYLOAD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N/AC:L"}}]},
    "weaknesses": [{"description": [{"value": "CWE-502"}]}],
}}]}


class CveExtractionTests(unittest.TestCase):
    def test_cves_of_reads_title_and_references(self):
        f = _finding(title="log4shell CVE-2021-44228 detected",
                     references=["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"])
        self.assertEqual(set(cveintel.cves_of(f)),
                         {"CVE-2021-44228", "CVE-2021-45046"})

    def test_cves_of_reads_structured_field(self):
        f = _finding(cves=["CVE-2020-1234"])
        self.assertEqual(cveintel.cves_of(f), ["CVE-2020-1234"])


class EnrichTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "cveintel.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _fake_http(self, url, **kwargs):
        if "epss" in url:
            return EPSS_PAYLOAD
        if "nvd" in url:
            return NVD_PAYLOAD
        raise AssertionError(f"unexpected url {url}")

    def test_online_enrichment_sets_epss_and_cvss(self):
        f = _finding(title="log4shell", cves=["CVE-2021-44228"])
        with patch.object(cveintel, "_http_json", side_effect=self._fake_http), \
             patch.object(cveintel.time, "sleep", lambda *_: None):
            summary = cveintel.enrich([f], cache_path=self.cache, online=True,
                                      nvd_key="test-key")
        self.assertEqual(f.epss, 0.97)
        self.assertEqual(f.epss_percentile, 0.999)
        self.assertEqual(f.cvss, 10.0)
        self.assertEqual(f.cvss_vector, "CVSS:3.1/AV:N/AC:L")
        self.assertIn("CWE-502", f.cwe_ids)
        self.assertEqual(summary["epss"], 1)

    def test_offline_uses_cache_without_network(self):
        self.cache.write_text(json.dumps({
            "epss": {"CVE-2021-44228": {"epss": 0.5, "percentile": 0.9,
                                        "date": "2026-01-01"}},
            "nvd": {},
        }), encoding="utf-8")
        f = _finding(cves=["CVE-2021-44228"])
        with patch.object(cveintel, "_http_json") as http:
            cveintel.enrich([f], cache_path=self.cache, online=False)
        http.assert_not_called()
        self.assertEqual(f.epss, 0.5)

    def test_no_cves_makes_no_network_calls(self):
        f = _finding(title="generic exposure")
        with patch.object(cveintel, "_http_json") as http:
            cveintel.enrich([f], cache_path=self.cache, online=True)
        http.assert_not_called()
        self.assertIsNone(f.epss)

    def test_nvd_skipped_without_key_or_anon(self):
        f = _finding(cves=["CVE-2021-44228"])
        calls = []

        def fake_http(url, **kwargs):
            calls.append(url)
            return EPSS_PAYLOAD  # only EPSS should ever be requested

        with patch.object(cveintel, "_http_json", side_effect=fake_http), \
             patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("KPM_NVD_ANON", None)
            os.environ.pop("NVD_API_KEY", None)
            cveintel.enrich([f], cache_path=self.cache, online=True, nvd_key="")
        self.assertTrue(all("nvd" not in u for u in calls))
        self.assertIsNone(f.cvss)


class NucleiIntelTests(unittest.TestCase):
    def test_parse_nuclei_carries_cve_cwe_cvss(self):
        line = json.dumps({
            "template-id": "log4shell", "matched-at": "https://example.test/x",
            "info": {"name": "Log4Shell", "severity": "critical",
                     "classification": {"cve-id": ["CVE-2021-44228"],
                                        "cwe-id": ["cwe-502"],
                                        "cvss-score": 9.8,
                                        "cvss-metrics": "CVSS:3.1/AV:N"}},
        })
        f = cve_mod.parse_nuclei(line, "example.test")[0]
        self.assertEqual(f.cves, ["CVE-2021-44228"])
        self.assertEqual(f.cwe_ids, ["cwe-502"])
        self.assertEqual(f.cvss, 9.8)
        self.assertEqual(f.cvss_vector, "CVSS:3.1/AV:N")


if __name__ == "__main__":
    unittest.main()
