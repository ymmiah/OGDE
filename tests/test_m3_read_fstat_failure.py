"""M3 regression: checkpoint read descriptor cleanup on metadata failure."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ogde.core import SecurityError
from ogde.m3_checkpoint import read_checkpoint, write_checkpoint


@unittest.skipUnless(
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL"))
    and all(op in os.supports_dir_fd for op in (os.open, os.link, os.unlink)),
    "POSIX descriptor-relative checkpoint operations required",
)
class ReadMetadataFailureTests(unittest.TestCase):
    def test_checkpoint_fstat_failure_closes_file_descriptor(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "checkpoint.json"
            digest = write_checkpoint(target, 1)
            before = target.read_bytes()
            real_fstat = os.fstat
            opened = []
            calls = 0

            def fail_file_fstat(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    opened.append(fd)
                    raise OSError("synthetic checkpoint metadata failure")
                return real_fstat(fd)

            with mock.patch("ogde.m3_checkpoint.os.fstat", side_effect=fail_file_fstat):
                with self.assertRaisesRegex(SecurityError, "Checkpoint metadata unavailable or unsafe"):
                    read_checkpoint(target, expected_digest=digest)

            self.assertEqual(calls, 2)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                real_fstat(opened[0])
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(list(Path(root).iterdir()), [target])
            self.assertEqual(read_checkpoint(target, expected_digest=digest), 1)


if __name__ == "__main__":
    unittest.main()
