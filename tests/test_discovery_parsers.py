"""Tests for the feroxbuster / httpx discovery parsers added to the web profile."""

import unittest

from src.findings import parse_feroxbuster, parse_httpx


FEROX = """\
200      GET        1l        1w        3c http://example.test/
200      GET        5l       10w      120c http://example.test/.env
200      GET        2l        4w       40c http://example.test/robots.txt
301      GET        0l        0w        0c http://example.test/admin => http://example.test/admin/
404      GET       13l       32w      335c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
"""

HTTPX = (
    '{"url":"https://example.test","input":"example.test",'
    '"status_code":200,"title":"Home","webserver":"nginx",'
    '"tech":["Nginx","PHP"]}'
)


class FeroxbusterParserTests(unittest.TestCase):
    def test_paths_severity_and_base_skipped(self):
        findings = parse_feroxbuster(FEROX, "example.test",
                                     "http://example.test")
        by_path = {f.endpoint: f for f in findings}
        # The base URL itself is not a finding.
        self.assertNotIn("http://example.test/", by_path)
        # .env is promoted from the sensitive-path heuristic.
        self.assertEqual(by_path["http://example.test/.env"].severity, "high")
        # Redirects are informational.
        self.assertEqual(
            by_path["http://example.test/admin"].severity, "info"
        )
        # The auto-filter advisory line must not become a finding.
        self.assertEqual(len(findings), 3)


class HttpxParserTests(unittest.TestCase):
    def test_jsonl_fingerprint(self):
        findings = parse_httpx(HTTPX, "example.test")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.tool, "httpx")
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.endpoint, "https://example.test")
        self.assertIn("tech=", f.description)
        self.assertIn("nginx", f.description)

    def test_ignores_non_json_noise(self):
        self.assertEqual(parse_httpx("not json\n\n", "example.test"), [])


if __name__ == "__main__":
    unittest.main()
