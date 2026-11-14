"""Checkpoint publication must fail closed when parent metadata cannot be read."""
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
class CheckpointWriteParentMetadataFailureTests(unittest.TestCase):
    def test_parent_fstat_failure_is_security_error_and_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            real_close = os.close
            closed = []

            def track_close(fd):
                closed.append(fd)
                return real_close(fd)

            with patch(
                "ogde.m3_checkpoint.os.fstat",
                side_effect=OSError("synthetic parent metadata failure"),
            ), patch("ogde.m3_checkpoint.os.close", side_effect=track_close):
                with self.assertRaisesRegex(SecurityError, "directory missing or unsafe"):
                    write_checkpoint(target, 1)

            self.assertTrue(closed, "Parent descriptor must be closed")
            self.assertFalse(target.exists(), "Failed publication must not create checkpoint")
            self.assertFalse(
                any(Path(directory).iterdir()),
                "Failed publication must not leave staging files",
            )
            self.assertEqual(len(write_checkpoint(target, 1)), 64)


if __name__ == "__main__":
    unittest.main()
