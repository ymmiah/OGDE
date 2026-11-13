"""Synthetic checkpoint cleanup-failure regression; no external access."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


@unittest.skipUnless(
    os.name == "posix"
    and all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL"))
    and all(op in os.supports_dir_fd for op in (os.open, os.link, os.unlink)),
    "POSIX descriptor-relative checkpoint publication required",
)
class CheckpointCleanupFailureTests(unittest.TestCase):
    def test_failed_staging_unlink_does_not_accept_partially_published_state(self):
        # The final name may already exist when staging cleanup fails.
        # A surviving staging hard link must make read_checkpoint fail closed.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            real_unlink = os.unlink

            def fail_staging_unlink(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith(".ogde-checkpoint-"):
                    raise OSError("synthetic staging cleanup failure")
                return real_unlink(path, *args, **kwargs)

            with patch("ogde.m3_checkpoint.os.unlink",
                       side_effect=fail_staging_unlink):
                with self.assertRaisesRegex(OSError, "staging cleanup"):
                    write_checkpoint(target, 1)

            self.assertTrue(target.is_file())
            staging = [
                entry for entry in Path(directory).iterdir()
                if entry.name.startswith(".ogde-checkpoint-")
            ]
            self.assertEqual(len(staging), 1)
            self.assertEqual(os.stat(staging[0]).st_ino, os.stat(target).st_ino)
            self.assertEqual(os.stat(target).st_nlink, 2)
            with self.assertRaisesRegex(SecurityError, "hard links"):
                read_checkpoint(target, expected_digest=checkpoint_digest(1))


if __name__ == "__main__":
    unittest.main()
