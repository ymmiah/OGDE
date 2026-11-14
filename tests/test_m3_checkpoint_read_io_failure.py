"""Checkpoint read I/O errors fail closed and release the opened descriptor."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import read_checkpoint, write_checkpoint


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"),
    "Requires POSIX descriptor-relative checkpoint operations",
)
class CheckpointReadFailureTests(unittest.TestCase):
    def test_read_error_is_security_error_and_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            digest = write_checkpoint(path, 1)
            opened = []
            real_fdopen = os.fdopen

            class FailingReader:
                def __init__(self, fd):
                    self.fd = fd

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    os.close(self.fd)

                def read(self, size):
                    raise OSError("synthetic read failure")

            def fail_fdopen(fd, mode):
                self.assertEqual(mode, "rb")
                opened.append(fd)
                return FailingReader(fd)

            with patch("ogde.m3_checkpoint.os.fdopen", side_effect=fail_fdopen):
                with self.assertRaisesRegex(SecurityError, "could not be read safely"):
                    read_checkpoint(path, expected_digest=digest)

            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
            self.assertEqual(read_checkpoint(path, expected_digest=digest), 1)


if __name__ == "__main__":
    unittest.main()
