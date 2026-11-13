"""M3 checkpoints must reject aliases to the same inode.

The external digest authenticates bytes, not the filesystem link topology.
All fixtures are synthetic and confined to a private temporary directory.
"""
import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import read_checkpoint, write_checkpoint


@unittest.skipUnless(os.name == "posix", "POSIX hard-link semantics required")
class CheckpointHardLinkTests(unittest.TestCase):
    def test_second_hard_link_invalidates_previously_valid_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            alias = Path(directory) / "alias.json"
            digest = write_checkpoint(checkpoint, 1)
            self.assertEqual(read_checkpoint(checkpoint, expected_digest=digest), 1)
            os.link(checkpoint, alias)
            self.assertEqual(checkpoint.stat().st_nlink, 2)
            with self.assertRaisesRegex(SecurityError, "hard links"):
                read_checkpoint(checkpoint, expected_digest=digest)
            with self.assertRaisesRegex(SecurityError, "hard links"):
                read_checkpoint(alias, expected_digest=digest)
            alias.unlink()
            self.assertEqual(read_checkpoint(checkpoint, expected_digest=digest), 1)


if __name__ == "__main__":
    unittest.main()
