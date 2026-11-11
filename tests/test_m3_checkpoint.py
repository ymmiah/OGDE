"""Offline tests for M3 checkpoint boundaries; no network or publisher trust."""
import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "checkpoint.json"

    def test_roundtrip_with_external_digest(self):
        digest = write_checkpoint(self.path, 3, previous_revision=2)
        self.assertEqual(digest, checkpoint_digest(3))
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 3)

    def test_missing_independent_digest_rejected(self):
        write_checkpoint(self.path, 1)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest="")

    def test_tampered_revision_rejected(self):
        digest = write_checkpoint(self.path, 2)
        self.path.write_text('{"revision":9,"schema_version":1}\n')
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_rollback_rejected(self):
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 2, previous_revision=3)

    def test_existing_file_not_overwritten(self):
        digest = write_checkpoint(self.path, 2)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 3, previous_revision=2)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 2)

    def test_symlink_rejected(self):
        target = Path(self.tmp.name) / "target"
        target.write_text("untrusted")
        self.path.symlink_to(target)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 1)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=checkpoint_digest(1))

    def test_noncanonical_payload_rejected(self):
        self.path.write_bytes(b'{"schema_version":1, "revision":1}\n')
        if os.name == "posix":
            self.path.chmod(0o600)
        import hashlib
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_world_readable_rejected(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions only")
        digest = write_checkpoint(self.path, 1)
        self.path.chmod(0o644)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_invalid_revision_type_fails_closed(self):
        for invalid in (True, "2", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SecurityError):
                    write_checkpoint(self.path, invalid)


    def test_hardlinked_checkpoint_rejected(self):
        if os.name != "posix":
            self.skipTest("POSIX hard links only")
        digest = write_checkpoint(self.path, 1)
        alias = Path(self.tmp.name) / "checkpoint-alias.json"
        os.link(self.path, alias)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_directory_is_not_checkpoint(self):
        directory = Path(self.tmp.name) / "directory"
        directory.mkdir(mode=0o700)
        with self.assertRaises(SecurityError):
            read_checkpoint(directory, expected_digest=checkpoint_digest(1))

    def test_missing_checkpoint_rejected(self):
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=checkpoint_digest(1))


    def test_link_failure_cleans_temporary_file(self):
        """Interrupted publication must leave no misleading checkpoint."""
        from unittest.mock import patch

        with patch("ogde.m3_checkpoint.os.link", side_effect=OSError("simulated link failure")):
            with self.assertRaises(OSError):
                write_checkpoint(self.path, 4)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(Path(self.tmp.name).glob(".ogde-checkpoint-*")), [])

    def test_concurrent_destination_collision_preserves_existing_checkpoint(self):
        """Exclusive link failure must not overwrite another writer's state."""
        from unittest.mock import patch

        original_link = os.link

        def competing_writer(source, destination):
            # Simulate a competing writer publishing first.
            existing = Path(destination)
            existing.write_bytes(b"another writer's state")
            return original_link(source, destination)

        with patch("ogde.m3_checkpoint.os.link", side_effect=competing_writer):
            with self.assertRaises(FileExistsError):
                write_checkpoint(self.path, 4)
        self.assertEqual(self.path.read_bytes(), b"another writer's state")
        self.assertEqual(list(Path(self.tmp.name).glob(".ogde-checkpoint-*")), [])


    def test_oversized_checkpoint_rejected_before_read(self):
        """Bound untrusted file size even with a matching external digest."""
        import hashlib

        payload = b"x" * 4097
        self.path.write_bytes(payload)
        if os.name == "posix":
            self.path.chmod(0o600)
        with self.assertRaises(SecurityError):
            read_checkpoint(
                self.path, expected_digest=hashlib.sha256(payload).hexdigest()
            )

    def test_non_regular_fifo_rejected_without_blocking(self):
        """An attacker-controlled FIFO must not hang the local verifier."""
        if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
            self.skipTest("Non-blocking FIFO support required")
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=checkpoint_digest(1))

    def test_invalid_external_digest_rejected(self):
        """Malformed or absent external evidence must fail closed."""
        digest = write_checkpoint(self.path, 1)
        for invalid in ("", digest.upper(), "g" * 64, None, 123):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SecurityError):
                    read_checkpoint(self.path, expected_digest=invalid)

    def test_directory_fsync_failure_requires_external_reconciliation(self):
        """A post-publication durability error must not be mistaken for success.

        The checkpoint may already exist when the directory fsync fails.
        A caller must reconcile it with independently protected state;
        the writer must not delete a possibly published checkpoint.
        """
        if not hasattr(os, "O_DIRECTORY"):
            self.skipTest("Directory fsync is not supported")
        from unittest.mock import patch

        real_fsync = os.fsync
        calls = 0

        def fail_directory_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated directory durability failure")
            return real_fsync(fd)

        with patch("ogde.m3_checkpoint.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaises(OSError):
                write_checkpoint(self.path, 5)
        self.assertEqual(calls, 2)
        self.assertTrue(self.path.exists())
        self.assertEqual(
            read_checkpoint(self.path, expected_digest=checkpoint_digest(5)), 5
        )
        self.assertEqual(list(Path(self.tmp.name).glob(".ogde-checkpoint-*")), [])

if __name__ == "__main__":
    unittest.main()
