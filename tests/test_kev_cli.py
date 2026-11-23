"""Offline CLI contract: KEV digest integrity never becomes publisher trust."""
import contextlib
import hashlib
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path

from ogde.cli import parser, run
from ogde.core import SecurityError, canonical


class KEVCLIContractTests(unittest.TestCase):
    def test_local_receipt_and_digest_rejection(self):
        snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-31"}]}
        digest = hashlib.sha256(canonical(snapshot)).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "kev.json"
            receipt_path = Path(directory) / "receipt.json"
            source.write_text(json.dumps(snapshot), encoding="utf-8")
            args = parser().parse_args(["ingest-kev", "--file", str(source), "--sha256", digest, "--out", str(receipt_path)])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 0)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertTrue(receipt["integrity_verified"])
            self.assertFalse(receipt["publisher_authenticated"])
            self.assertEqual(receipt["decision"], "human-review")
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            with self.assertRaises(SecurityError):
                run(parser().parse_args(["ingest-kev", "--file", str(source), "--sha256", "0" * 64]))
            self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), receipt)
            missing_receipt = Path(directory) / "must-not-exist.json"
            with self.assertRaises(SecurityError):
                run(parser().parse_args(["ingest-kev", "--file", str(source), "--sha256", "0" * 64, "--out", str(missing_receipt)]))
            self.assertFalse(missing_receipt.exists())

    def test_receipt_cannot_overwrite_source_or_alias(self):
        snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-31"}]}
        digest = hashlib.sha256(canonical(snapshot)).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "kev.json"
            original = json.dumps(snapshot)
            source.write_text(original, encoding="utf-8")
            alias = Path(directory) / "kev-link.json"
            alias.symlink_to(source)
            for destination in (source, alias):
                with self.subTest(destination=str(destination)):
                    args = parser().parse_args(["ingest-kev", "--file", str(source), "--sha256", digest, "--out", str(destination)])
                    with self.assertRaisesRegex(SecurityError, "must differ"):
                        run(args)
                    self.assertEqual(source.read_text(encoding="utf-8"), original)
            hardlink = Path(directory) / "kev-hardlink.json"
            hardlink.hardlink_to(source)
            args = parser().parse_args(["ingest-kev", "--file", str(source), "--sha256", digest, "--out", str(hardlink)])
            with self.assertRaisesRegex(SecurityError, "must differ"):
                run(args)
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_receipt_refuses_unrelated_symlink(self):
        snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-31"}]}
        digest = hashlib.sha256(canonical(snapshot)).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "kev.json"
            target = Path(directory) / "other-evidence.json"
            destination = Path(directory) / "receipt-link.json"
            source.write_text(json.dumps(snapshot), encoding="utf-8")
            target.write_text("untouched", encoding="utf-8")
            destination.symlink_to(target)
            with self.assertRaisesRegex(SecurityError, "symlink"):
                run(parser().parse_args(["ingest-kev", "--file", str(source), "--sha256", digest, "--out", str(destination)]))
            self.assertEqual(target.read_text(encoding="utf-8"), "untouched")

    def test_no_network_or_implicit_trust_options(self):
        args = parser().parse_args(["ingest-kev", "--file", "local.json", "--sha256", "a" * 64])
        self.assertEqual(args.cmd, "ingest-kev")
        self.assertFalse(hasattr(args, "confirm_trust_anchor"))
        self.assertFalse(hasattr(args, "confirm_inventory_sharing"))


if __name__ == "__main__":
    unittest.main()
