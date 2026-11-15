"""M3 checkpoint filesystem-boundary regression tests (offline, POSIX only)."""

import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


@unittest.skipUnless(os.name == "posix", "POSIX filesystem security semantics")
class CheckpointFilesystemBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.target = self.state / "checkpoint.json"

    def test_hardlinked_checkpoint_is_rejected(self):
        digest = write_checkpoint(self.target, 2)
        os.link(self.target, self.state / "alias.json")
        with self.assertRaises(SecurityError):
            read_checkpoint(self.target, expected_digest=digest)

    def test_symlinked_checkpoint_is_rejected(self):
        digest = write_checkpoint(self.target, 2)
        link = self.state / "link.json"
        link.symlink_to(self.target)
        with self.assertRaises(SecurityError):
            read_checkpoint(link, expected_digest=digest)

    def test_symlinked_ancestor_is_rejected_for_read_and_write(self):
        digest = write_checkpoint(self.target, 2)
        alias = self.root / "alias"
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(SecurityError):
            read_checkpoint(alias / "checkpoint.json", expected_digest=digest)
        with self.assertRaises(SecurityError):
            write_checkpoint(alias / "new.json", 3, previous_revision=2)

    def test_noncanonical_checkpoint_is_rejected_even_with_matching_digest(self):
        import hashlib
        self.target.write_bytes(b'{"revision":2, "schema_version":1}\n')
        self.target.chmod(0o600)
        digest = hashlib.sha256(self.target.read_bytes()).hexdigest()
        with self.assertRaises(SecurityError):
            read_checkpoint(self.target, expected_digest=digest)

    def test_checkpoint_revision_digest_is_deterministic(self):
        self.assertEqual(write_checkpoint(self.target, 2), checkpoint_digest(2))


if __name__ == "__main__":
    unittest.main()
