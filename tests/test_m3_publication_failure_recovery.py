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
                with self.assertRaisesRegex(OSError, "simulated link failure"):
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


if __name__ == "__main__":
    unittest.main()
