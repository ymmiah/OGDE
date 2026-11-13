"""M3 regression: descriptor ownership when stream wrapping fails."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ogde.m3_checkpoint import write_checkpoint


@unittest.skipUnless(
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL"))
    and all(op in os.supports_dir_fd for op in (os.open, os.link, os.unlink)),
    "POSIX descriptor-relative checkpoint operations required",
)
class StagingDescriptorTests(unittest.TestCase):
    def test_fdopen_failure_closes_staging_descriptor_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "checkpoint.json"
            captured = []

            def fail_fdopen(fd, mode):
                captured.append(fd)
                raise OSError("synthetic fdopen failure")

            with mock.patch("ogde.m3_checkpoint.os.fdopen", side_effect=fail_fdopen):
                with self.assertRaisesRegex(OSError, "synthetic fdopen failure"):
                    write_checkpoint(target, 1)

            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                os.fstat(captured[0])
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(root).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
