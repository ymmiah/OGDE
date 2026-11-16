"""Offline regression for M3 checkpoint staging durability failures."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import write_checkpoint


class StagingDurabilityTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX descriptor publication only")
    def test_staging_fsync_failure_fails_closed_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "checkpoint.json"
            with patch("ogde.m3_checkpoint.os.fsync",
                       side_effect=OSError("simulated staging fsync failure")) as sync, \
                 patch("ogde.m3_checkpoint.os.link") as publish:
                with self.assertRaisesRegex(
                    SecurityError, "staging write or sync failed"
                ):
                    write_checkpoint(destination, 1)
            sync.assert_called_once()
            publish.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertEqual(
                list(Path(directory).glob(".ogde-checkpoint-*")), []
            )
