"""M3 checkpoint file metadata failure must fail closed without leaking descriptors."""
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
class CheckpointFileMetadataFailureTests(unittest.TestCase):
    def test_file_fstat_failure_is_security_error_and_closes_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkpoint.json"
            digest = write_checkpoint(target, 1)
            real_fstat = os.fstat
            real_close = os.close
            file_fds = []
            closed = []

            def fail_second_fstat(fd):
                # First fstat verifies the parent; the second verifies the file.
                if file_fds:
                    raise OSError("synthetic checkpoint metadata failure")
                file_fds.append(fd)
                return real_fstat(fd)

            def track_close(fd):
                closed.append(fd)
                return real_close(fd)

            with patch("ogde.m3_checkpoint.os.fstat", side_effect=fail_second_fstat), patch(
                "ogde.m3_checkpoint.os.close", side_effect=track_close
            ):
                with self.assertRaisesRegex(SecurityError, "metadata unavailable or unsafe"):
                    read_checkpoint(target, expected_digest=digest)

            # The parent descriptor and checkpoint descriptor must both be closed.
            self.assertGreaterEqual(len(closed), 2)
            self.assertNotEqual(closed[-1], closed[-2])
            self.assertEqual(read_checkpoint(target, expected_digest=digest), 1)


if __name__ == "__main__":
    unittest.main()
