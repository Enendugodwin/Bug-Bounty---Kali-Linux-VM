"""Tests for the redesigned web GUI page (ui-ux-pro-max design system)."""

import unittest

from starlette.testclient import TestClient

from src import webgui


class GuiMarkupTests(unittest.TestCase):
    def test_page_renders_with_design_system_and_infra_profile(self):
        with TestClient(webgui.app) as client:
            r = client.get("/")
        self.assertEqual(r.status_code, 200)
        html = r.text
        self.assertIn('value="infra"', html)          # infra selectable in GUI
        self.assertIn('value="web"', html)            # web profile selectable
        self.assertIn('id="findings"', html)          # findings viewer panel
        self.assertIn("loadFindings", html)           # findings loader JS
        self.assertIn('id="logview"', html)           # live log panel
        self.assertIn("logFromSnapshot", html)        # live log wiring
        self.assertIn("#i-shield", html)              # SVG icon sprite
        self.assertIn("Fira Code", html)              # design-system typography
        self.assertIn("prefers-reduced-motion", html)
        self.assertNotIn("\u25c8", html)              # no ◈ glyph
        self.assertNotIn("\u25b6", html)              # no ▶ glyph
        self.assertNotIn("\u2b07", html)              # no ⬇ glyph

    def test_scope_check_endpoint_responds(self):
        with TestClient(webgui.app) as client:
            r = client.get("/api/scope/check",
                           params={"target": "not-in-scope.example"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("allowed", r.json())


if __name__ == "__main__":
    unittest.main()
