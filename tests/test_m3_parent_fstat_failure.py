"""M3 read must fail closed and release its parent descriptor on fstat failure."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import read_checkpoint, write_checkpoint


@unittest.skipUnless(
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
    and os.open in os.supports_dir_fd,
    "POSIX descriptor-relative checkpoint reads required",
)
class ParentMetadataFailureTests(unittest.TestCase):
    def test_parent_fstat_failure_is_security_error_and_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            digest = write_checkpoint(target, 1)
            original_fstat = os.fstat
            original_close = os.close
            opened = []
            closed = []

            def track_fstat(fd):
                opened.append(fd)
                raise OSError("synthetic parent metadata failure")

            def track_close(fd):
                closed.append(fd)
                return original_close(fd)

            with patch("ogde.m3_checkpoint.os.fstat", side_effect=track_fstat), patch(
                "ogde.m3_checkpoint.os.close", side_effect=track_close
            ):
                with self.assertRaisesRegex(SecurityError, "directory missing or unsafe"):
                    read_checkpoint(target, expected_digest=digest)

            self.assertEqual(len(opened), 1)
            self.assertIn(opened[0], closed)
            self.assertEqual(read_checkpoint(target, expected_digest=digest), 1)


if __name__ == "__main__":
    unittest.main()
