"""Offline tests for M3 checkpoint boundaries; no network or publisher trust."""
import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "checkpoint.json"

    def test_roundtrip_with_external_digest(self):
        digest = write_checkpoint(self.path, 3, previous_revision=2)
        self.assertEqual(digest, checkpoint_digest(3))
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 3)

    def test_missing_independent_digest_rejected(self):
        write_checkpoint(self.path, 1)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest="")

    def test_tampered_revision_rejected(self):
        digest = write_checkpoint(self.path, 2)
        self.path.write_text('{"revision":9,"schema_version":1}\n')
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_rollback_rejected(self):
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 2, previous_revision=3)

    def test_existing_file_not_overwritten(self):
        digest = write_checkpoint(self.path, 2)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 3, previous_revision=2)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 2)

    def test_symlink_rejected(self):
        target = Path(self.tmp.name) / "target"
        target.write_text("untrusted")
        self.path.symlink_to(target)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 1)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=checkpoint_digest(1))

    def test_noncanonical_payload_rejected(self):
        self.path.write_bytes(b'{"schema_version":1, "revision":1}\n')
        if os.name == "posix":
            self.path.chmod(0o600)
        import hashlib
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_world_readable_rejected(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions only")
        digest = write_checkpoint(self.path, 1)
        self.path.chmod(0o644)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_invalid_revision_type_fails_closed(self):
        for invalid in (True, "2", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SecurityError):
                    write_checkpoint(self.path, invalid)


if __name__ == "__main__":
    unittest.main()
