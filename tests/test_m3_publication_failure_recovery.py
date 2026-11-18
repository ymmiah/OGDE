"""Failure recovery for descriptor-relative M3 checkpoint publication.

All tests use a private temporary directory and synthetic failures only.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import write_checkpoint


@unittest.skipUnless(
    os.name == "posix" and all(
        hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL")
    ) and all(op in os.supports_dir_fd for op in (os.open, os.link, os.unlink)),
    "POSIX descriptor-relative checkpoint publication required",
)
class CheckpointPublicationFailureTests(unittest.TestCase):
    def test_failed_exclusive_link_removes_staging_and_target(self):
        """An interrupted link must not leave a candidate checkpoint behind."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            with patch("ogde.m3_checkpoint.os.link",
                       side_effect=OSError("simulated link failure")) as link:
                with self.assertRaisesRegex(SecurityError, "Checkpoint publication failed safely"):
                    write_checkpoint(target, 1)
            link.assert_called_once()
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_failed_staging_open_does_not_create_checkpoint(self):
        """Exclusive staging failure must not create the final name."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            original_open = os.open

            def fail_staging(path, flags, *args, **kwargs):
                if isinstance(path, str) and path.startswith(".ogde-checkpoint-"):
                    raise OSError("simulated staging failure")
                return original_open(path, flags, *args, **kwargs)

            with patch("ogde.m3_checkpoint.os.open", side_effect=fail_staging):
                with self.assertRaisesRegex(SecurityError, "Checkpoint staging file could not be created safely"):
                    write_checkpoint(target, 1)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])


    def test_staging_cleanup_failure_requires_human_review(self):
        """A published name with failed cleanup must not report success."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            original_unlink = os.unlink

            def fail_staging_cleanup(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith(".ogde-checkpoint-"):
                    raise OSError("simulated cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with patch("ogde.m3_checkpoint.os.unlink", side_effect=fail_staging_cleanup):
                with self.assertRaisesRegex(SecurityError, "publication state requires human review"):
                    write_checkpoint(target, 1)
            self.assertTrue(target.exists())
            self.assertEqual(len(list(Path(directory).iterdir())), 2)

    def test_directory_sync_failure_does_not_report_durable_success(self):
        """Directory fsync failure is not a verified checkpoint commit."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            original_fsync = os.fsync
            calls = 0

            def fail_directory_sync(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated directory sync failure")
                return original_fsync(fd)

            with patch("ogde.m3_checkpoint.os.fsync", side_effect=fail_directory_sync):
                with self.assertRaisesRegex(SecurityError, "publication durability unverified"):
                    write_checkpoint(target, 1)
            self.assertTrue(target.exists())
            self.assertEqual(len(list(Path(directory).iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
