"""Reject special-file checkpoint substitution without blocking on POSIX."""
import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde import m3_checkpoint


@unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO required")
class CheckpointNonblockingTests(unittest.TestCase):
    def test_fifo_is_rejected_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint"
            os.mkfifo(checkpoint, 0o600)
            with self.assertRaises(SecurityError):
                m3_checkpoint.read_checkpoint(
                    checkpoint, expected_digest=m3_checkpoint.checkpoint_digest(1)
                )
            self.assertTrue(checkpoint.is_fifo())


if __name__ == "__main__":
    unittest.main()
