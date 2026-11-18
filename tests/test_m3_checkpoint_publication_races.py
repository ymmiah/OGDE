"""M3 checkpoint publication race regression (offline, POSIX only)."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.m3_checkpoint import write_checkpoint


@unittest.skipUnless(os.name == "posix", "POSIX descriptor-relative publication")
class CheckpointPublicationRaceTests(unittest.TestCase):
    def test_exclusive_link_collision_fails_closed_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            target = state / "checkpoint.json"
            with patch("ogde.m3_checkpoint.os.link", side_effect=FileExistsError("collision")):
                with self.assertRaisesRegex(SecurityError, "publication failed safely"):
                    write_checkpoint(target, 2)
            self.assertFalse(target.exists())
            self.assertEqual(list(state.iterdir()), [])

    def test_publication_io_error_fails_closed_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            target = state / "checkpoint.json"
            with patch("ogde.m3_checkpoint.os.link", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(SecurityError, "publication failed safely"):
                    write_checkpoint(target, 2)
            self.assertFalse(target.exists())
            self.assertEqual(list(state.iterdir()), [])
