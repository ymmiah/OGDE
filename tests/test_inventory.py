"""Local inventory collectors: versions in, secrets never read."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.inventory import collect_inventory


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo-site"
CANARIES = (
    "OGDE-DEMO-INDEX-CANARY",
    "OGDE-DEMO-PLUGIN-BODY-CANARY",
    "OGDE-DEMO-SECRET-CANARY",
    "OGDE-DEMO-THEME-BODY-CANARY",
    "SUPER-SECRET-CANARY",
    "DB_PASSWORD",
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class InventoryTests(unittest.TestCase):
    def test_demo_site_collects_only_versions(self):
        opened = []
        chunks = []
        real_open = os.open
        real_read = os.read

        def spy_open(path, flags, *args, **kwargs):
            opened.append(os.fspath(path))
            return real_open(path, flags, *args, **kwargs)

        def spy_read(fd, size):
            data = real_read(fd, size)
            chunks.append(data)
            return data

        os.open = spy_open
        os.read = spy_read
        try:
            bom = collect_inventory(
                wordpress=str(DEMO / "wordpress"),
                composer_lock=str(DEMO / "composer.lock"),
                package_lock=str(DEMO / "package-lock.json"),
            )
        finally:
            os.open = real_open
            os.read = real_read

        purls = {item["purl"] for item in bom["components"]}
        self.assertEqual(purls, {
            "pkg:wordpress/core@6.7.1",
            "pkg:wordpress/plugin/hello-ogde@1.0.0",
            "pkg:wordpress/theme/ogde-demo@1.0.0",
            "pkg:composer/ogde/synthetic-demo@1.2.3",
            "pkg:composer/ogde/synthetic-dev@0.1.0",
            "pkg:npm/ogde-synthetic-site@0.0.0",
            "pkg:npm/ogde-synthetic-leftpad@1.0.0",
        })
        encoded = json.dumps(bom)
        for canary in CANARIES:
            self.assertNotIn(canary, encoded)
        self.assertNotIn(str(DEMO), encoded)
        unread = ("OGDE-DEMO-INDEX-CANARY", "OGDE-DEMO-SECRET-CANARY")
        self.assertTrue(all(canary.encode() not in blob for blob in chunks for canary in unread))
        scopes = {item["purl"]: item.get("properties") for item in bom["components"]}
        self.assertEqual(scopes["pkg:composer/ogde/synthetic-dev@0.1.0"], [{"name": "ogde:dependency-scope", "value": "dev"}])
        wordpress = next(item for item in bom["components"] if item["purl"].startswith("pkg:wordpress/"))
        self.assertNotIn("properties", wordpress)
        names = {Path(path).name for path in opened}
        self.assertNotIn("index.php", names)
        self.assertNotIn("secret.php", names)
        self.assertEqual(bom["metadata"]["properties"][0], {"name": "ogde:inventory-scope", "value": "local-only"})
        self.assertEqual(bom["metadata"]["properties"][1], {"name": "ogde:transmitted", "value": "false"})

    def test_refuses_secret_files_and_does_not_open_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "wp-includes" / "version.php", "<?php\n$wp_version = '6.7.1';\n")
            _write(root / "wp-config.php", "<?php\ndefine('DB_PASSWORD', 'SUPER-SECRET-CANARY');\n")
            _write(root / ".env", "DB_PASSWORD=SUPER-SECRET-CANARY\n")
            _write(root / "id_rsa", "-----BEGIN PRIVATE KEY-----\nSUPER-SECRET-CANARY\n")
            _write(root / "wp-content" / "uploads" / "customers.sql", "SUPER-SECRET-CANARY")
            _write(root / "wp-content" / "plugins" / "hello-ogde" / "hello-ogde.php", "<?php\n/*\nVersion: 1.2.0\n*/\n")
            _write(root / "wp-content" / "plugins" / "hello-ogde" / "includes" / "db.php", "SUPER-SECRET-CANARY")
            _write(root / "wp-content" / "themes" / "ogde-demo" / "style.css", "/*\nVersion: 2.0.0\n*/\n")
            opened = []
            real_open = os.open

            def spy_open(path, flags, *args, **kwargs):
                opened.append(os.fspath(path))
                return real_open(path, flags, *args, **kwargs)

            os.open = spy_open
            try:
                bom = collect_inventory(wordpress=str(root))
            finally:
                os.open = real_open
            encoded = json.dumps(bom)
            self.assertNotIn("SUPER-SECRET-CANARY", encoded)
            self.assertNotIn("DB_PASSWORD", encoded)
            opened_names = {Path(path).name for path in opened}
            self.assertTrue(opened_names.isdisjoint({"wp-config.php", ".env", "id_rsa", "customers.sql", "db.php"}))
            self.assertEqual(
                {item["purl"] for item in bom["components"]},
                {"pkg:wordpress/core@6.7.1", "pkg:wordpress/plugin/hello-ogde@1.2.0", "pkg:wordpress/theme/ogde-demo@2.0.0"},
            )

    def test_symlink_version_file_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "site"
            outside = Path(tmp) / "secret.php"
            _write(root / "wp-content" / "plugins" / ".keep", "")
            outside.write_text("<?php\n$wp_version = '9.9.9';\nSUPER-SECRET-CANARY\n", encoding="utf-8")
            link = root / "wp-includes" / "version.php"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(outside)
            with self.assertRaises(SecurityError) as caught:
                collect_inventory(wordpress=str(root))
            self.assertNotIn("SUPER-SECRET-CANARY", str(caught.exception))

    def test_version_past_header_window_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            padding = b"/* pad */\n" * 1000
            payload = padding + b"$wp_version = '1.2.3';\nSUPER-SECRET-CANARY\n"
            self.assertGreater(len(payload), 8192)
            path = root / "wp-includes" / "version.php"
            path.parent.mkdir(parents=True)
            path.write_bytes(payload)
            chunks = []
            real_read = os.read

            def spy_read(fd, size):
                data = real_read(fd, size)
                chunks.append(data)
                return data

            os.read = spy_read
            try:
                with self.assertRaises(SecurityError) as caught:
                    collect_inventory(wordpress=str(root))
            finally:
                os.read = real_read
            self.assertNotIn("SUPER-SECRET-CANARY", str(caught.exception))
            self.assertNotIn("1.2.3", str(caught.exception))
            self.assertTrue(all(b"SUPER-SECRET-CANARY" not in blob for blob in chunks))

    def test_lockfile_discards_urls_and_rejects_bad_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            composer = root / "composer.lock"
            composer.write_text(json.dumps({
                "packages": [{
                    "name": "ogde/synthetic-demo",
                    "version": "1.2.3",
                    "dist": {"url": "https://example.invalid/package.zip?token=SUPER-SECRET-CANARY"},
                }],
            }), encoding="utf-8")
            npm = root / "package-lock.json"
            npm.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "resolved": "https://example.invalid/left.tgz?token=SUPER-SECRET-CANARY",
                    },
                },
            }), encoding="utf-8")
            bom = collect_inventory(composer_lock=str(composer), package_lock=str(npm))
            encoded = json.dumps(bom)
            self.assertNotIn("SUPER-SECRET-CANARY", encoded)
            self.assertNotIn("example.invalid", encoded)
            self.assertIn("pkg:npm/left-pad@1.3.0", encoded)
            composer.write_text(json.dumps({"packages": [{"name": "$(id)", "version": "1.0.0"}]}), encoding="utf-8")
            with self.assertRaises(SecurityError) as caught:
                collect_inventory(composer_lock=str(composer))
            self.assertNotIn("$(id)", str(caught.exception))

    def test_rejects_symlink_lockfile_wrong_name_and_old_npm_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / ".env"
            env.write_text("SUPER-SECRET-CANARY", encoding="utf-8")
            link = root / "composer.lock"
            link.symlink_to(env)
            with self.assertRaises(SecurityError) as caught:
                collect_inventory(composer_lock=str(link))
            self.assertNotIn("SUPER-SECRET-CANARY", str(caught.exception))
            config = root / "wp-config.php"
            config.write_text("SUPER-SECRET-CANARY", encoding="utf-8")
            with self.assertRaises(SecurityError):
                collect_inventory(composer_lock=str(config))
            old = root / "package-lock.json"
            old.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}), encoding="utf-8")
            with self.assertRaises(SecurityError) as caught:
                collect_inventory(package_lock=str(old))
            self.assertIn("lockfileVersion 2 or 3", str(caught.exception))

    def test_cli_writes_private_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "inventory.json"
            completed = subprocess.run(
                [sys.executable, "-m", "ogde", "inventory",
                 "--wordpress", str(DEMO / "wordpress"),
                 "--composer-lock", str(DEMO / "composer.lock"),
                 "--package-lock", str(DEMO / "package-lock.json"),
                 "--out", str(out)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("pkg:wordpress/core@6.7.1", out.read_text(encoding="utf-8"))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertNotIn("OGDE-DEMO-SECRET-CANARY", out.read_text(encoding="utf-8"))

    def test_modules_do_not_reference_network_or_databases(self):
        for name in ("inventory.py", "finding.py", "localio.py"):
            text = (ROOT / "src" / "ogde" / name).read_text(encoding="utf-8")
            for banned in ("import subprocess", "import socket", "urllib.request", "import requests", "import sqlite3", "psycopg", "pymysql", "eval(", "exec("):
                self.assertNotIn(banned, text, name)


if __name__ == "__main__":
    unittest.main()
