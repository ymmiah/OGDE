"""Fail closed before filesystem access when POSIX nonblocking support is absent."""
import os
import unittest
from unittest import mock

from ogde.core import SecurityError
from ogde import m3_checkpoint


@unittest.skipUnless(os.name == "posix", "POSIX capability gate required")
class CheckpointNonblockingCapabilityTests(unittest.TestCase):
    def test_missing_nonblocking_flag_rejected_before_open(self):
        actual_hasattr = hasattr

        def capability_present(obj, name):
            if obj is os and name == "O_NONBLOCK":
                return False
            return actual_hasattr(obj, name)

        with mock.patch("ogde.m3_checkpoint.hasattr", capability_present, create=True):
            with mock.patch.object(m3_checkpoint.os, "open") as opened:
                with self.assertRaisesRegex(SecurityError, "operations unavailable"):
                    m3_checkpoint.read_checkpoint(
                        "/unused/checkpoint",
                        expected_digest=m3_checkpoint.checkpoint_digest(1),
                    )
                opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
