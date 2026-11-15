"""M3 checkpoint regression tests; no local file grants publisher trust."""
import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


class M3CheckpointIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / "revision.json"

    def test_independent_digest_is_required(self):
        digest = write_checkpoint(self.path, 4)
        self.assertEqual(digest, checkpoint_digest(4))
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 4)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest="0" * 64)

    def test_local_content_tampering_is_rejected(self):
        digest = write_checkpoint(self.path, 4)
        self.path.write_bytes(b'{"revision":5,"schema_version":1}\n')
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_overwrite_and_revision_rollback_are_rejected(self):
        write_checkpoint(self.path, 4)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 5, previous_revision=4)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.directory / "other.json", 4, previous_revision=4)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.directory / "negative.json", 3, previous_revision=4)

    def test_invalid_digest_and_revision_types_are_rejected(self):
        for revision in (True, 0, -1, 2**53 + 1, 1.5):
            with self.subTest(revision=revision):
                with self.assertRaises(SecurityError):
                    checkpoint_digest(revision)
        for supplied in (None, "A" * 64, "f" * 63, "g" * 64):
            with self.subTest(digest=supplied):
                with self.assertRaises(SecurityError):
                    read_checkpoint(self.path, expected_digest=supplied)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_world_readable_checkpoint_is_rejected(self):
        digest = write_checkpoint(self.path, 1)
        self.path.chmod(0o644)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)


if __name__ == "__main__":
    unittest.main()
