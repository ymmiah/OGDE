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

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor publication only")
    def test_staging_write_failure_fails_closed_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "checkpoint.json"
            original_fdopen = os.fdopen

            class FailingWriter:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    self.handle.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def write(self, data):
                    raise OSError("simulated staging write failure")

                def flush(self):
                    return self.handle.flush()

                def fileno(self):
                    return self.handle.fileno()

            def failing_fdopen(fd, mode):
                handle = original_fdopen(fd, mode)
                return FailingWriter(handle) if mode == "wb" else handle

            with patch("ogde.m3_checkpoint.os.fdopen", side_effect=failing_fdopen), \
                 patch("ogde.m3_checkpoint.os.link") as publish:
                with self.assertRaisesRegex(
                    SecurityError, "staging write or sync failed"
                ):
                    write_checkpoint(destination, 1)
            publish.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertEqual(
                list(Path(directory).glob(".ogde-checkpoint-*")), []
            )

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor publication only")
    def test_staging_flush_failure_never_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "checkpoint.json"
            original_fdopen = os.fdopen

            class FailingFlush:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    self.handle.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def write(self, data):
                    return self.handle.write(data)

                def flush(self):
                    raise OSError("simulated staging flush failure")

                def fileno(self):
                    return self.handle.fileno()

            def failing_fdopen(fd, mode):
                handle = original_fdopen(fd, mode)
                return FailingFlush(handle) if mode == "wb" else handle

            with patch("ogde.m3_checkpoint.os.fdopen", side_effect=failing_fdopen), \
                 patch("ogde.m3_checkpoint.os.link") as publish:
                with self.assertRaisesRegex(SecurityError, "staging write or sync failed"):
                    write_checkpoint(destination, 1)
            publish.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".ogde-checkpoint-*")), [])


    @unittest.skipUnless(os.name == "posix", "POSIX descriptor publication only")
    def test_staging_fdopen_failure_fails_closed_without_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "checkpoint.json"
            with patch("ogde.m3_checkpoint.os.fdopen",
                       side_effect=OSError("simulated staging fdopen failure")), \
                 patch("ogde.m3_checkpoint.os.link") as publish:
                with self.assertRaisesRegex(
                    SecurityError, "staging writer could not be opened safely"
                ):
                    write_checkpoint(destination, 1)
            publish.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".ogde-checkpoint-*")), [])

