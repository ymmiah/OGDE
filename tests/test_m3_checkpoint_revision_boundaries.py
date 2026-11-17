"""Offline M3 checkpoint revision-boundary regression tests.

The revision is an exact integer within the JSON interoperability range.
A malformed caller value must never create checkpoint state.
"""
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


class CheckpointRevisionBoundaryTests(unittest.TestCase):
    def test_digest_rejects_non_integer_and_out_of_range_revisions(self):
        for invalid in (False, True, 0, -1, 2**53 + 1, 1.0, "1", None):
            with self.subTest(value=repr(invalid)):
                with self.assertRaises(SecurityError):
                    checkpoint_digest(invalid)

    def test_write_rejects_invalid_new_revision_without_side_effects(self):
        invalid_revisions = (False, True, 0, -1, 2**53 + 1, 1.0, "1", None)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            for revision in invalid_revisions:
                with self.subTest(revision=repr(revision)):
                    with self.assertRaises(SecurityError):
                        write_checkpoint(path, revision)
                    self.assertFalse(path.exists())
                    self.assertEqual(list(Path(directory).glob(".ogde-checkpoint-*")), [])

    def test_initial_revision_with_zero_previous_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            digest = write_checkpoint(path, 1, previous_revision=0)
            self.assertEqual(digest, checkpoint_digest(1))
            self.assertEqual(read_checkpoint(path, expected_digest=digest), 1)

    def test_maximum_revision_round_trip_requires_external_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            digest = write_checkpoint(path, 2**53, previous_revision=2**53 - 1)
            self.assertEqual(digest, checkpoint_digest(2**53))
            self.assertEqual(read_checkpoint(path, expected_digest=digest), 2**53)

    def test_previous_revision_requires_exact_integer_and_monotonicity(self):
        invalid_previous = (False, True, 0.0, 1.0, "1", None, -1, 2, 3)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            for previous in invalid_previous:
                with self.subTest(previous=repr(previous)):
                    with self.assertRaises(SecurityError):
                        write_checkpoint(path, 2, previous_revision=previous)
                    self.assertFalse(path.exists())
                    self.assertEqual(list(Path(directory).glob(".ogde-checkpoint-*")), [])


if __name__ == "__main__":
    unittest.main()
