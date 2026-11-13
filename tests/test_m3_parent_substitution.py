"""Synthetic parent-directory substitution tests; no external network access."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


@unittest.skipUnless(
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL"))
    and all(op in os.supports_dir_fd for op in (os.open, os.link, os.unlink)),
    "POSIX descriptor-relative checkpoint operations required",
)
class ParentSubstitutionTests(unittest.TestCase):
    def test_publication_rejects_different_opened_parent_inode(self):
        # Simulate the parent being substituted between path validation and
        # descriptor traversal. The replacement must never receive staging data.
        with tempfile.TemporaryDirectory() as root:
            original = Path(root) / "original"
            replacement = Path(root) / "replacement"
            original.mkdir(mode=0o700)
            replacement.mkdir(mode=0o700)
            target = original / "checkpoint.json"
            opened = []

            def substituted_parent(_path):
                fd = os.open(replacement, os.O_RDONLY | os.O_DIRECTORY)
                opened.append(fd)
                return fd

            with mock.patch("ogde.m3_checkpoint._open_parent_chain",
                            side_effect=substituted_parent):
                with self.assertRaisesRegex(SecurityError, "changed or unsafe"):
                    write_checkpoint(target, 1)
            self.assertEqual(list(original.iterdir()), [])
            self.assertEqual(list(replacement.iterdir()), [])
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])

    def test_read_rejects_different_opened_parent_inode(self):
        with tempfile.TemporaryDirectory() as root:
            original = Path(root) / "original"
            replacement = Path(root) / "replacement"
            original.mkdir(mode=0o700)
            replacement.mkdir(mode=0o700)
            target = original / "checkpoint.json"
            opened = []

            def substituted_parent(_path):
                fd = os.open(replacement, os.O_RDONLY | os.O_DIRECTORY)
                opened.append(fd)
                return fd

            with mock.patch("ogde.m3_checkpoint._open_parent_chain",
                            side_effect=substituted_parent):
                with self.assertRaisesRegex(SecurityError, "changed or unsafe"):
                    read_checkpoint(target, expected_digest=checkpoint_digest(1))
            self.assertEqual(list(original.iterdir()), [])
            self.assertEqual(list(replacement.iterdir()), [])
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])


if __name__ == "__main__":
    unittest.main()
