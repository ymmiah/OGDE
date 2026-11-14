"""Checkpoint staging creation errors must fail closed without leaked state."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import write_checkpoint


@unittest.skipUnless(
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL"))
    and all(op in os.supports_dir_fd for op in (os.open, os.link, os.unlink)),
    "POSIX descriptor-relative checkpoint publication required",
)
class CheckpointStagingOpenFailureTests(unittest.TestCase):
    def test_staging_open_failure_closes_parent_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            real_open = os.open
            real_close = os.close
            parent_fds = []
            closed = []

            def fail_staging_open(path, flags, *args, **kwargs):
                if str(path).startswith(".ogde-checkpoint-"):
                    raise OSError("synthetic staging creation failure")
                fd = real_open(path, flags, *args, **kwargs)
                parent_fds.append(fd)
                return fd

            def track_close(fd):
                closed.append(fd)
                return real_close(fd)

            # The mock replaces os.open and therefore cannot appear in
            # os.supports_dir_fd; the real capability check runs on recovery.
            with patch("ogde.m3_checkpoint._require_posix_dirfd"), patch(
                "ogde.m3_checkpoint.os.open", side_effect=fail_staging_open
            ), patch("ogde.m3_checkpoint.os.close", side_effect=track_close):
                with self.assertRaisesRegex(SecurityError, "staging file could not be created safely"):
                    write_checkpoint(target, 1)

            self.assertTrue(parent_fds)
            self.assertIn(parent_fds[-1], closed)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])
            digest = write_checkpoint(target, 1)
            self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
