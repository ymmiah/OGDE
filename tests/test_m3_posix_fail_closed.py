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

    def test_publication_requires_each_descriptor_relative_primitive(self):
        # A platform may support dir_fd for open but not for link or unlink.
        # Reject before opening a staging file rather than using path fallback.
        required = (os.open, os.link, os.unlink)
        for missing in required:
            with self.subTest(missing=missing.__name__):
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "checkpoint.json"
                    capabilities = set(os.supports_dir_fd) - {missing}
                    with mock.patch.object(os, "supports_dir_fd", capabilities):
                        with self.assertRaisesRegex(SecurityError, "Descriptor-relative"):
                            write_checkpoint(target, 1)
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_read_rejects_missing_directory_or_nofollow_flags(self):
        # Capability checks must precede any pathname access.
        for flag in ("O_DIRECTORY", "O_NOFOLLOW"):
            with self.subTest(flag=flag):
                with mock.patch.object(os, flag):
                    delattr(os, flag)
                    with self.assertRaisesRegex(SecurityError, "Descriptor-relative"):
                        read_checkpoint("/nonexistent/checkpoint.json",
                                        expected_digest=checkpoint_digest(1))

    def test_write_rejects_missing_required_flags_without_staging(self):
        for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL"):
            with self.subTest(flag=flag):
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "checkpoint.json"
                    with mock.patch.object(os, flag):
                        delattr(os, flag)
                        with self.assertRaisesRegex(SecurityError, "Descriptor-relative"):
                            write_checkpoint(target, 1)
                    self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
