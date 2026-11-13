"""Smoke-test both installed CLI names without network or production access."""
import shutil
import subprocess
import unittest


class InstalledEntrypointTests(unittest.TestCase):
    def test_both_cli_names_are_installed_and_read_only(self):
        for name in ("ogde", "odge"):
            with self.subTest(entrypoint=name):
                executable = shutil.which(name)
                self.assertIsNotNone(executable, f"{name} entrypoint missing from PATH")
                version = subprocess.run(
                    [executable, "--version"], capture_output=True, text=True,
                    timeout=15, check=False,
                )
                self.assertEqual(version.returncode, 0, version.stderr)
                self.assertTrue(version.stdout.strip())
                help_result = subprocess.run(
                    [executable, "--help"], capture_output=True, text=True,
                    timeout=15, check=False,
                )
                self.assertEqual(help_result.returncode, 0, help_result.stderr)
                self.assertIn("scan-osv", help_result.stdout)
                self.assertIn("inventory", help_result.stdout)

    def test_both_aliases_reject_unconsented_online_scan(self):
        # Consent must be checked before reading an SBOM or making a request.
        for name in ("ogde", "odge"):
            with self.subTest(entrypoint=name):
                executable = shutil.which(name)
                self.assertIsNotNone(executable, f"{name} entrypoint missing from PATH")
                result = subprocess.run(
                    [executable, "scan-osv", "--sbom", "nonexistent-synthetic-sbom.json"],
                    capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("--confirm-inventory-sharing", result.stderr)


if __name__ == "__main__":
    unittest.main()
