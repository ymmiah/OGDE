"""Offline CLI contract: KEV digest integrity never becomes publisher trust."""
import contextlib
import hashlib
import io
import json
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
            with self.assertRaises(SecurityError):
                run(parser().parse_args(["ingest-kev", "--file", str(source), "--sha256", "0" * 64]))
            self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), receipt)

    def test_no_network_or_implicit_trust_options(self):
        args = parser().parse_args(["ingest-kev", "--file", "local.json", "--sha256", "a" * 64])
        self.assertEqual(args.cmd, "ingest-kev")
        self.assertFalse(hasattr(args, "confirm_trust_anchor"))
        self.assertFalse(hasattr(args, "confirm_inventory_sharing"))


if __name__ == "__main__":
    unittest.main()
