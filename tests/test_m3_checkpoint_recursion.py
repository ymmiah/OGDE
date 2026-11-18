"""Regression: malformed deeply nested checkpoint JSON fails closed."""
import hashlib
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import read_checkpoint


class CheckpointRecursionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX descriptor traversal only")
    def test_ancestor_open_failure_is_security_error(self):
        # The directory can disappear or be swapped after lstat checks.
        # Simulate a failed descriptor traversal without weakening validation.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            with mock.patch("ogde.m3_checkpoint._open_parent_chain",
                            side_effect=OSError("simulated traversal failure")):
                with self.assertRaises(SecurityError) as raised:
                    read_checkpoint(path, expected_digest="0" * 64)
        self.assertIsInstance(raised.exception.__cause__, OSError)

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


    def test_json_decoder_recursion_failure_is_security_error(self):
        # Object nesting beyond the decoder's recursion limit exceeds the
        # 4096-byte checkpoint cap. Instead, inject the decoder failure
        # after verifying a correctly sized, correctly hashed checkpoint.
        raw = b'{"revision":1,"schema_version":1}\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_bytes(raw)
            if os.name == "posix":
                os.chmod(path, 0o600)
            digest = hashlib.sha256(raw).hexdigest()
            with mock.patch("ogde.m3_checkpoint.json.loads",
                            side_effect=RecursionError("simulated decoder depth")) as decoder:
                with self.assertRaises(SecurityError):
                    read_checkpoint(path, expected_digest=digest)
            decoder.assert_called_once_with(raw)

if __name__ == "__main__":
    unittest.main()
