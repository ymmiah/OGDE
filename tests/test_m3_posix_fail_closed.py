"""POSIX checkpoint operations must never downgrade to pathname fallback."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


@unittest.skipUnless(os.name == "posix", "POSIX descriptor requirements")
class CheckpointFailClosedTests(unittest.TestCase):
    def test_read_rejects_missing_dirfd_before_path_access(self):
        with mock.patch.object(os, "supports_dir_fd", set()):
            with self.assertRaisesRegex(SecurityError, "Descriptor-relative"):
                read_checkpoint("/nonexistent/checkpoint.json",
                                expected_digest=checkpoint_digest(1))

    def test_write_rejects_missing_dirfd_without_creating_state(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            with mock.patch.object(os, "supports_dir_fd", {os.open}):
                with self.assertRaisesRegex(SecurityError, "Descriptor-relative"):
                    write_checkpoint(target, 1)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
