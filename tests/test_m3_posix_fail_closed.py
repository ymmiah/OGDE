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


    def test_staging_fsync_failure_cleans_up_without_publication(self):
        # A failed durability barrier must never publish the checkpoint.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            with mock.patch("ogde.m3_checkpoint.os.fsync",
                            side_effect=OSError("synthetic staging fsync failure")):
                with self.assertRaises(OSError):
                    write_checkpoint(target, 1)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_directory_fsync_failure_requires_manual_reconciliation(self):
        # The final link may already exist when directory durability fails.
        # An exception is not evidence that publication was rolled back.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            real_fsync = os.fsync
            calls = []

            def fail_directory_sync(fd):
                calls.append(fd)
                if len(calls) == 2:
                    raise OSError("synthetic directory durability failure")
                return real_fsync(fd)

            with mock.patch("ogde.m3_checkpoint.os.fsync",
                            side_effect=fail_directory_sync):
                with self.assertRaisesRegex(OSError, "directory durability"):
                    write_checkpoint(target, 1)

            self.assertEqual(len(calls), 2)
            self.assertTrue(target.is_file())
            self.assertEqual(read_checkpoint(
                target, expected_digest=checkpoint_digest(1)), 1)
            self.assertEqual([p.name for p in Path(directory).iterdir()],
                             ["checkpoint.json"])

    def test_exclusive_link_failure_closes_parent_descriptor(self):
        # The parent directory fd must be released even on failed publication.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            import ogde.m3_checkpoint as checkpoint
            real_open_parent = checkpoint._open_parent_chain
            opened = []

            def tracked_open(path):
                fd = real_open_parent(path)
                opened.append(fd)
                return fd

            with mock.patch.object(checkpoint, "_open_parent_chain",
                                   side_effect=tracked_open):
                with mock.patch.object(checkpoint.os, "link",
                                       side_effect=FileExistsError("synthetic race")):
                    with self.assertRaises(FileExistsError):
                        write_checkpoint(target, 1)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_missing_checkpoint_read_closes_parent_descriptor(self):
        # A failed descriptor-relative final open must release the parent fd.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "missing.json"
            import ogde.m3_checkpoint as checkpoint
            real_open_parent = checkpoint._open_parent_chain
            opened = []

            def tracked_open(path):
                fd = real_open_parent(path)
                opened.append(fd)
                return fd

            with mock.patch.object(checkpoint, "_open_parent_chain",
                                   side_effect=tracked_open):
                with self.assertRaises(SecurityError):
                    read_checkpoint(target, expected_digest=checkpoint_digest(1))
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
            self.assertEqual(list(Path(directory).iterdir()), [])

if __name__ == "__main__":
    unittest.main()
