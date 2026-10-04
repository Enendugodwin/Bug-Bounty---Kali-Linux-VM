"""Tests for the infra (firewalls/Windows/switches/Linux) scanner."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import infra
from src import jobs


NMAP = """\
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 9.6
445/tcp  open  microsoft-ds  Windows Server 2019
161/tcp  open  snmp          net-snmp
"""


class ServiceParseTests(unittest.TestCase):
    def test_open_services(self):
        svc = infra._open_services(NMAP)
        self.assertEqual(svc[22], "ssh")
        self.assertEqual(svc[445], "microsoft-ds")
        self.assertEqual(svc[161], "snmp")


class ParserTests(unittest.TestCase):
    def test_onesixtyone_default_community_is_medium(self):
        f = infra.parse_onesixtyone("10.0.0.1 [public]", "10.0.0.1")[0]
        self.assertEqual(f.severity, "medium")
        self.assertIn("public", f.title)

    def test_showmount_exports(self):
        out = "Export list for h:\n/data  *\n/srv   10.0.0.0/24"
        findings = infra.parse_showmount(out, "h")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "medium")

    def test_nxc_smb_signing_and_positive_lines(self):
        text = (
            "SMB  10.0.0.1  445  DC  [*] Windows Server\n"
            "SMB  10.0.0.1  445  DC  [+] signing:False\n"
            "SMB  10.0.0.1  445  DC  [+] domain\\user\n"
        )
        findings = infra.parse_nxc(text, "10.0.0.1")
        titles = " ".join(f.title.lower() for f in findings)
        self.assertIn("signing", titles)
        self.assertTrue(any(f.severity == "medium" for f in findings))

    def test_snmpwalk_sysdescr(self):
        out = "SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software\n"
        findings = infra.parse_snmpwalk(out, "sw")
        self.assertEqual(findings[0].severity, "low")
        self.assertIn("sysDescr", findings[0].title)

    def test_ikescan_responder(self):
        out = "Starting ike-scan 1.9\n10.0.0.1\tHandshake returned"
        findings = infra.parse_ikescan(out, "10.0.0.1")
        self.assertEqual(findings[0].severity, "info")

    def test_nmap_nse_lines(self):
        out = "| ssh-hostkey: \n|_  2048 SHA256:abc (RSA)\n"
        findings = infra.parse_nmap_nse(out, "h")
        self.assertTrue(findings)
        self.assertTrue(all(f.severity == "info" for f in findings))

    def test_enum4linux_ng_json(self):
        payload = {"users": {"alice": {}, "bob": {}},
                   "shares": {"ADMIN$": {"access": "DENIED"},
                              "Public": {"access": "READ"}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "e4l.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            findings = infra.parse_enum4linux_ng(path, "dc")
        titles = " ".join(f.title for f in findings)
        self.assertIn("users enumerated (2)", titles)
        self.assertIn("shares enumerated", titles)


class InfraGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = jobs.DB_PATH
        self.old_init = jobs._INITIALIZED_PATH
        jobs.DB_PATH = Path(self.tmp.name) / "infra.sqlite3"
        jobs._INITIALIZED_PATH = None

    def tearDown(self):
        jobs.DB_PATH = self.old_db
        jobs._INITIALIZED_PATH = self.old_init
        self.tmp.cleanup()

    def test_out_of_scope_is_denied_without_running_tools(self):
        fake = SimpleNamespace(rules={}, program={},
                               check=lambda _t: (False, "not listed"))
        with patch.object(infra.scope, "get_scope", return_value=fake), \
             patch.object(infra.runner, "run") as run:
            a = infra.run_infra("evil.example", reports_dir=Path(self.tmp.name))
        run.assert_not_called()
        self.assertFalse(a.authorized)
        self.assertEqual(a.scan_status, "denied")

    def test_intrusive_requires_confirmation(self):
        fake = SimpleNamespace(rules={"allow_intrusive": True}, program={},
                               check=lambda _t: (True, "authorized"))
        with patch.object(infra.scope, "get_scope", return_value=fake):
            with self.assertRaises(PermissionError):
                infra.run_infra("example.test", include_intrusive=True,
                                confirm_intrusive=False)

    def test_intrusive_requires_scope_authorization(self):
        fake = SimpleNamespace(rules={"allow_intrusive": False}, program={},
                               check=lambda _t: (True, "authorized"))
        with patch.object(infra.scope, "get_scope", return_value=fake):
            with self.assertRaises(PermissionError):
                infra.run_infra("example.test", include_intrusive=True,
                                confirm_intrusive=True)

    def test_happy_path_discovers_services_and_selects_tools(self):
        fake = SimpleNamespace(
            rules={"max_requests_per_second": 5, "allowed_ports": []},
            program={}, check=lambda _t: (True, "test scope"))

        def fake_run(argv, **kwargs):
            out = NMAP if argv[0] == "nmap" else ""
            return SimpleNamespace(command=argv, stdout=out, stderr="",
                                   exit_code=0, duration_ms=1,
                                   artifact_path=None)

        with patch.object(infra.scope, "get_scope", return_value=fake), \
             patch.object(infra.runner, "run", side_effect=fake_run), \
             patch.object(infra.memory.memory, "add_document", return_value=None):
            a = infra.run_infra("example.test",
                                reports_dir=Path(self.tmp.name) / "reports")
        self.assertTrue(a.authorized)
        self.assertEqual(a.profile, "infra")
        tools = {c["tool"] for c in a.commands}
        self.assertIn("nmap", tools)
        self.assertIn("enum4linux-ng", tools)   # SMB branch
        # detection is not a vuln on its own
        self.assertTrue(all(f.tool in tools for f in a.findings))


if __name__ == "__main__":
    unittest.main()
