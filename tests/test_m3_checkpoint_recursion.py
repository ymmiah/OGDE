"""Regression: malformed deeply nested checkpoint JSON fails closed."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import read_checkpoint


class CheckpointRecursionTests(unittest.TestCase):
    def test_nested_json_with_matching_digest_is_security_error(self):
        # Small enough to satisfy the 4096-byte checkpoint limit, but deep
        # enough to exceed CPython's JSON decoder recursion threshold.
        raw = (b"[" * 1500) + b"0" + (b"]" * 1500)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_bytes(raw)
            if os.name == "posix":
                os.chmod(path, 0o600)
            digest = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(SecurityError):
                read_checkpoint(path, expected_digest=digest)


if __name__ == "__main__":
    unittest.main()
