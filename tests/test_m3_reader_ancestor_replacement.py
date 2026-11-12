"""Adversarial offline tests for M3 descriptor-relative checkpoint reads."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import read_checkpoint, write_checkpoint


class ReaderAncestorReplacementTests(unittest.TestCase):
    def test_real_directory_replacement_during_walk_fails_closed(self):
        """A genuine replacement directory must not redirect a verified read."""
        if not (os.name == "posix" and hasattr(os, "O_DIRECTORY")
                and hasattr(os, "O_NOFOLLOW")
                and os.open in os.supports_dir_fd):
            self.skipTest("POSIX descriptor-relative traversal required")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_parent = root / "outer" / "inner"
            original_parent.mkdir(parents=True)
            replacement = root / "replacement"
            (replacement / "inner").mkdir(parents=True)
            checkpoint = original_parent / "checkpoint.json"
            digest = write_checkpoint(checkpoint, 6)
            # A valid digest must not authorise a different directory inode.
            write_checkpoint(replacement / "inner" / "checkpoint.json", 6)

            real_open = os.open
            swapped = False

            def replace_before_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if (path == "outer" and kwargs.get("dir_fd") is not None
                        and not swapped):
                    swapped = True
                    (root / "outer").rename(root / "old-outer")
                    replacement.rename(root / "outer")
                return real_open(path, flags, *args, **kwargs)

            with patch("ogde.m3_checkpoint.os.open", side_effect=replace_before_open):
                with self.assertRaises(SecurityError):
                    read_checkpoint(checkpoint, expected_digest=digest)

            self.assertTrue(swapped)
            self.assertEqual(
                read_checkpoint(root / "old-outer" / "inner" / "checkpoint.json",
                                expected_digest=digest), 6
            )


if __name__ == "__main__":
    unittest.main()
