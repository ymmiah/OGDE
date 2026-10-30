"""OGDE canonical branding regression tests and ODGE legacy compatibility."""
import unittest
import subprocess
import sys

class BrandingTests(unittest.TestCase):
    def test_canonical_cli_version(self):
        p = subprocess.run([sys.executable, "-m", "ogde", "--version"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("0.2.2", p.stdout)

    def test_legacy_cli_version(self):
        p = subprocess.run([sys.executable, "-m", "odge", "--version"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("0.2.2", p.stdout)

    def test_legacy_module_api(self):
        import odge.core as old
        import ogde.core as current
        self.assertIs(old.SecurityError, current.SecurityError)

    def test_brand_parser(self):
        from ogde.cli import parser
        self.assertEqual(parser().prog, "ogde")

if __name__ == "__main__":
    unittest.main()

class PublicIdentityTests(unittest.TestCase):
    def test_project_name_in_readme(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn("# OGDE — One Global Defence Ecosystem", readme)
        self.assertIn("ymmiah/OGDE", (root / "docs/GITHUB_PUBLISH.md").read_text(encoding="utf-8"))
