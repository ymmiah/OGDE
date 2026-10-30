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
        import odge.inventory as old_inventory
        import ogde.inventory as current_inventory
        self.assertIs(old.SecurityError, current.SecurityError)
        self.assertEqual(current.__name__, "ogde.core")
        self.assertEqual(current.__spec__.name, "ogde.core")
        self.assertIs(old_inventory.collect_inventory, current_inventory.collect_inventory)

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
        self.assertIn("OGDE — One Global Defence Ecosystem", readme)
        self.assertIn("assets/brand/ogde-logo.png", readme)
        self.assertNotIn("source publication pending", readme.lower())
        self.assertIn("ymmiah/OGDE", (root / "docs/GITHUB_PUBLISH.md").read_text(encoding="utf-8"))
        publish = (root / "docs/GITHUB_PUBLISH.md").read_text(encoding="utf-8").lower()
        self.assertNotIn("has not been pushed", publish)
        names = sorted(path.name for path in (root / "src/odge").glob("*.py"))
        self.assertEqual(names, ["__init__.py", "__main__.py"])

    def test_brand_assets_and_static_site(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        logo = root / "assets/brand/ogde-logo.jpg"
        png = (root / "assets/brand/ogde-logo.png").read_bytes()
        svg = (root / "assets/brand/ogde-logo.svg").read_text(encoding="utf-8")
        brand = (root / "assets/brand/README.md").read_text(encoding="utf-8")
        self.assertTrue(logo.read_bytes().startswith(b"\xff\xd8\xff"))
        self.assertEqual(png[12:16], b"IHDR")
        self.assertEqual(png[25], 6)
        self.assertIn('fill="#052355"', svg)
        self.assertIn("One Global Defence Ecosystem", svg)
        self.assertIn("#052355", brand)
        self.assertIn("#717580", brand)
        self.assertIn("https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-logo.png", brand)
        page = (root / "site/index.html").read_text(encoding="utf-8")
        lowered = page.lower()
        self.assertNotIn("<script", lowered)
        self.assertNotIn("<form", lowered)
        self.assertIn("../assets/brand/ogde-logo.svg", page)
        hosting = (root / "site/README.md").read_text(encoding="utf-8")
        self.assertIn("ogde.org", hosting)
        self.assertIn("Cloudflare", hosting)
