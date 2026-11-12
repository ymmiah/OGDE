"""POSIX descriptor lifetime regressions for offline M3 checkpoint traversal."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.m3_checkpoint import _open_parent_chain


class AncestorDescriptorLifetimeTests(unittest.TestCase):
    def test_failed_intermediate_open_closes_previous_descriptor(self):
        """An interrupted directory walk must not leak an open ancestor fd."""
        if not (os.name == "posix" and hasattr(os, "O_DIRECTORY")
                and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd):
            self.skipTest("POSIX descriptor-relative traversal required")

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "outer" / "inner"
            parent.mkdir(parents=True)
            original_open = os.open
            acquired = []
            failed = False

            def fail_intermediate(path, flags, *args, **kwargs):
                nonlocal failed
                if path == "inner" and kwargs.get("dir_fd") is not None:
                    failed = True
                    raise OSError("simulated intermediate directory failure")
                fd = original_open(path, flags, *args, **kwargs)
                acquired.append(fd)
                return fd

            with patch("ogde.m3_checkpoint.os.open", side_effect=fail_intermediate):
                with self.assertRaises(OSError):
                    _open_parent_chain(parent)

            self.assertTrue(failed)
            self.assertGreater(len(acquired), 0)
            for fd in acquired:
                with self.subTest(fd=fd):
                    with self.assertRaises(OSError):
                        os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
