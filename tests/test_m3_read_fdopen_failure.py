"""M3 regression: read descriptor ownership when stream wrapping fails."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


@unittest.skipUnless(
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL"))
    and all(op in os.supports_dir_fd for op in (os.open, os.link, os.unlink)),
    "POSIX descriptor-relative checkpoint operations required",
)
class ReadDescriptorTests(unittest.TestCase):
    def test_fdopen_failure_closes_read_descriptor_without_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "checkpoint.json"
            digest = write_checkpoint(target, 1)
            before = target.read_bytes()
            captured = []

            def fail_fdopen(fd, mode):
                captured.append(fd)
                raise OSError("synthetic read fdopen failure")

            with mock.patch("ogde.m3_checkpoint.os.fdopen", side_effect=fail_fdopen):
                with self.assertRaisesRegex(OSError, "synthetic read fdopen failure"):
                    read_checkpoint(target, expected_digest=digest)

            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                os.fstat(captured[0])
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(list(Path(root).iterdir()), [target])
            self.assertEqual(read_checkpoint(target, expected_digest=checkpoint_digest(1)), 1)


if __name__ == "__main__":
    unittest.main()
