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

    def test_foreign_owned_checkpoint_rejected(self):
        """An otherwise valid digest must not bypass inode ownership checks."""
        if os.name != "posix":
            self.skipTest("POSIX ownership only")
        from types import SimpleNamespace
        from unittest.mock import patch

        digest = write_checkpoint(self.path, 1)
        real_fstat = os.fstat

        def foreign_owner(fd):
            metadata = os.stat_result(real_fstat(fd))
            fields = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid",
                      "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")
            values = {field: getattr(metadata, field) for field in fields}
            values["st_uid"] = os.geteuid() + 1
            return SimpleNamespace(**values)

        with patch("ogde.m3_checkpoint.os.fstat", side_effect=foreign_owner):
            with self.assertRaises(SecurityError):
                read_checkpoint(self.path, expected_digest=digest)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_parent_descriptor_inode_mismatch_rejected(self):
        """A parent replacement between lstat and open must fail closed."""
        if os.name != "posix" or not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")):
            self.skipTest("POSIX descriptor-relative directory checks required")
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch

        digest = write_checkpoint(self.path, 1)
        real_fstat = os.fstat

        def replaced_parent(fd):
            metadata = real_fstat(fd)
            if stat.S_ISDIR(metadata.st_mode):
                return SimpleNamespace(
                    st_mode=metadata.st_mode, st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino + 1, st_uid=metadata.st_uid
                )
            return metadata

        with patch("ogde.m3_checkpoint.os.fstat", side_effect=replaced_parent):
            with self.assertRaises(SecurityError):
                read_checkpoint(self.path, expected_digest=digest)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_parent_descriptor_permissions_mismatch_rejected(self):
        """Reject a parent made group-writable after the initial path check."""
        if os.name != "posix" or not all(
            hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")
        ):
            self.skipTest("POSIX descriptor-relative directory checks required")
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch

        digest = write_checkpoint(self.path, 1)
        real_fstat = os.fstat

        def widened_parent(fd):
            metadata = real_fstat(fd)
            if stat.S_ISDIR(metadata.st_mode):
                return SimpleNamespace(
                    st_mode=metadata.st_mode | 0o020,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_uid=metadata.st_uid,
                )
            return metadata

        with patch("ogde.m3_checkpoint.os.fstat", side_effect=widened_parent):
            with self.assertRaises(SecurityError):
                read_checkpoint(self.path, expected_digest=digest)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_read_rejects_foreign_owned_parent(self):
        """A valid external digest cannot authorise a foreign-owned directory."""
        if os.name != "posix":
            self.skipTest("POSIX directory ownership only")
        from types import SimpleNamespace
        from unittest.mock import patch

        digest = write_checkpoint(self.path, 1)
        original_lstat = Path.lstat

        def foreign_parent(path, *args, **kwargs):
            metadata = original_lstat(path, *args, **kwargs)
            if Path(path) == self.path.parent:
                return SimpleNamespace(
                    st_mode=metadata.st_mode, st_uid=os.geteuid() + 1
                )
            return metadata

        with patch("ogde.m3_checkpoint.Path.lstat", autospec=True,
                   side_effect=foreign_parent):
            with self.assertRaises(SecurityError):
                read_checkpoint(self.path, expected_digest=digest)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_read_rejects_world_writable_parent(self):
        if os.name != "posix":
            self.skipTest("POSIX directory permissions only")
        digest = write_checkpoint(self.path, 1)
        self.path.parent.chmod(0o777)
        self.addCleanup(self.path.parent.chmod, 0o700)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)

    def test_read_rejects_group_writable_parent(self):
        """A group member must not be able to swap checkpoint entries."""
        if os.name != "posix":
            self.skipTest("POSIX directory permissions only")
        digest = write_checkpoint(self.path, 1)
        parent = self.path.parent
        parent.chmod(0o770)
        self.addCleanup(parent.chmod, 0o700)
        with self.assertRaises(SecurityError):
            read_checkpoint(self.path, expected_digest=digest)
        parent.chmod(0o700)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_read_rejects_symlinked_parent(self):
        real = Path(self.tmp.name) / "real"
        real.mkdir(mode=0o700)
        original = real / "checkpoint.json"
        digest = write_checkpoint(original, 1)
        alias = Path(self.tmp.name) / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(SecurityError):
            read_checkpoint(alias / "checkpoint.json", expected_digest=digest)

    def test_read_rejects_intermediate_symlink_ancestor(self):
        real = Path(self.tmp.name) / "real"
        nested = real / "nested"
        nested.mkdir(parents=True, mode=0o700)
        original = nested / "checkpoint.json"
        digest = write_checkpoint(original, 1)
        alias = Path(self.tmp.name) / "alias"
        try:
            alias.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symlinks unavailable")
        with self.assertRaises(SecurityError):
            read_checkpoint(alias / "nested" / "checkpoint.json", expected_digest=digest)

    def test_write_rejects_intermediate_symlink_ancestor(self):
        """Publication must not follow a redirected ancestor directory."""
        real = Path(self.tmp.name) / "real"
        nested = real / "nested"
        nested.mkdir(parents=True, mode=0o700)
        alias = Path(self.tmp.name) / "alias"
        try:
            alias.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symlinks unavailable")
        destination = alias / "nested" / "checkpoint.json"
        with self.assertRaises(SecurityError):
            write_checkpoint(destination, 1)
        self.assertFalse((nested / "checkpoint.json").exists())
        self.assertEqual(list(nested.glob(".ogde-checkpoint-*")), [])

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

        def competing_writer(source, destination, **kwargs):
            # Simulate a competing writer publishing first in the same dirfd.
            if "dst_dir_fd" in kwargs:
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=kwargs["dst_dir_fd"])
                with os.fdopen(fd, "wb") as handle:
                    handle.write(b"another writer's state")
            else:
                Path(destination).write_bytes(b"another writer's state")
            return original_link(source, destination, **kwargs)

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

    def test_write_rejects_foreign_owned_parent(self):
        """A foreign-owned directory must not receive a checkpoint."""
        if os.name != "posix":
            self.skipTest("POSIX directory ownership only")
        from types import SimpleNamespace
        from unittest.mock import patch

        real_stat = Path.stat

        def foreign_parent(path, *args, **kwargs):
            metadata = real_stat(path, *args, **kwargs)
            if Path(path) == self.path.parent:
                return SimpleNamespace(
                    st_mode=metadata.st_mode, st_uid=os.geteuid() + 1
                )
            return metadata

        with patch("ogde.m3_checkpoint.Path.stat", autospec=True,
                   side_effect=foreign_parent):
            with self.assertRaises(SecurityError):
                write_checkpoint(self.path, 1)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.glob(".ogde-checkpoint-*")), [])
        digest = write_checkpoint(self.path, 1)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_write_rejects_parent_descriptor_inode_mismatch(self):
        """A swapped parent inode must fail before temporary file creation."""
        if os.name != "posix" or not all(
            hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")
        ):
            self.skipTest("POSIX descriptor checks required")
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch

        real_fstat = os.fstat

        def swapped_parent(fd):
            metadata = real_fstat(fd)
            if stat.S_ISDIR(metadata.st_mode):
                return SimpleNamespace(
                    st_mode=metadata.st_mode, st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino + 1, st_uid=metadata.st_uid
                )
            return metadata

        with patch("ogde.m3_checkpoint.os.fstat", side_effect=swapped_parent):
            with self.assertRaises(SecurityError):
                write_checkpoint(self.path, 1)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.glob(".ogde-checkpoint-*")), [])
        digest = write_checkpoint(self.path, 1)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_write_rejects_parent_descriptor_permission_change(self):
        """A permission change after stat must fail before staging files."""
        if os.name != "posix" or not all(
            hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")
        ):
            self.skipTest("POSIX descriptor checks required")
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch

        real_fstat = os.fstat

        def widened_parent(fd):
            metadata = real_fstat(fd)
            if stat.S_ISDIR(metadata.st_mode):
                return SimpleNamespace(
                    st_mode=metadata.st_mode | 0o020,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_uid=metadata.st_uid,
                )
            return metadata

        with patch("ogde.m3_checkpoint.os.fstat", side_effect=widened_parent):
            with self.assertRaises(SecurityError):
                write_checkpoint(self.path, 1)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.glob(".ogde-checkpoint-*")), [])
        digest = write_checkpoint(self.path, 1)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 1)

    def test_shared_writable_parent_rejected(self):
        """A second local user must not control checkpoint directory entries."""
        if os.name != "posix":
            self.skipTest("POSIX directory permissions only")
        parent = self.path.parent
        parent.chmod(0o777)
        self.addCleanup(parent.chmod, 0o700)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 1)
        self.assertFalse(self.path.exists())

    def test_group_writable_parent_rejected(self):
        if os.name != "posix":
            self.skipTest("POSIX directory permissions only")
        parent = self.path.parent
        parent.chmod(0o770)
        self.addCleanup(parent.chmod, 0o700)
        with self.assertRaises(SecurityError):
            write_checkpoint(self.path, 1)
        self.assertFalse(self.path.exists())

    def test_writer_uses_single_verified_parent_descriptor(self):
        """Publication must not reopen its parent after descriptor validation."""
        if not (os.name == "posix" and hasattr(os, "O_DIRECTORY")
                and hasattr(os, "O_NOFOLLOW")
                and os.open in os.supports_dir_fd
                and os.link in os.supports_dir_fd
                and os.unlink in os.supports_dir_fd):
            self.skipTest("Descriptor-relative POSIX publication required")
        from unittest.mock import patch

        real_open = os.open
        parent_opens = []

        def observe_open(path, flags, *args, **kwargs):
            if Path(path) == self.path.parent and flags & os.O_DIRECTORY:
                parent_opens.append(path)
            return real_open(path, flags, *args, **kwargs)

        with patch("ogde.m3_checkpoint.os.open", side_effect=observe_open):
            digest = write_checkpoint(self.path, 8)
        self.assertEqual(len(parent_opens), 1)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 8)

    def test_staging_file_is_exclusive_private_and_descriptor_relative(self):
        """Checkpoint staging must never use a path-based or shared file."""
        if not (os.name == "posix" and hasattr(os, "O_DIRECTORY")
                and hasattr(os, "O_NOFOLLOW")
                and os.open in os.supports_dir_fd
                and os.link in os.supports_dir_fd
                and os.unlink in os.supports_dir_fd):
            self.skipTest("Descriptor-relative POSIX publication required")
        from unittest.mock import patch

        real_open = os.open
        staging_calls = []

        def inspect_open(path, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                staging_calls.append((path, flags, args, kwargs))
                self.assertTrue(flags & os.O_EXCL)
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertEqual(args[0] if args else None, 0o600)
                parent_fd = kwargs.get("dir_fd")
                self.assertIsInstance(parent_fd, int)
                self.assertTrue(Path(path).name.startswith(".ogde-checkpoint-"))
                self.assertEqual(Path(path).name, str(path))
                self.assertEqual(os.fstat(parent_fd).st_ino,
                                 self.path.parent.stat().st_ino)
            return real_open(path, flags, *args, **kwargs)

        # Mocking os.open changes its identity; preserve dir_fd registration
        # for the instrumented callable so this tests the POSIX path.
        with patch("ogde.m3_checkpoint.os.open", side_effect=inspect_open) as mocked_open:
            with patch("ogde.m3_checkpoint.os.supports_dir_fd",
                       new=os.supports_dir_fd | {mocked_open}):
                digest = write_checkpoint(self.path, 9)
        self.assertEqual(len(staging_calls), 1)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 9)
        self.assertEqual(list(self.path.parent.glob(".ogde-checkpoint-*")), [])

    def test_directory_sync_follows_staging_cleanup(self):
        """Directory fsync must observe no leftover staging entry."""
        if not (os.name == "posix" and hasattr(os, "O_DIRECTORY")
                and os.open in os.supports_dir_fd
                and os.link in os.supports_dir_fd
                and os.unlink in os.supports_dir_fd):
            self.skipTest("Descriptor-relative POSIX publication required")
        from unittest.mock import patch
        import stat

        real_fsync = os.fsync
        directory_syncs = []

        def inspect_directory_at_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                directory_syncs.append(True)
                self.assertEqual(
                    list(self.path.parent.glob(".ogde-checkpoint-*")), [],
                    "Staging entry must be removed before directory fsync",
                )
                self.assertTrue(self.path.exists())
            return real_fsync(fd)

        with patch("ogde.m3_checkpoint.os.fsync",
                   side_effect=inspect_directory_at_sync):
            digest = write_checkpoint(self.path, 7)
        self.assertEqual(directory_syncs, [True])
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 7)
        self.assertEqual(list(self.path.parent.glob(".ogde-checkpoint-*")), [])

    def test_staging_write_failure_does_not_publish(self):
        """A short/failed staging write must never publish a checkpoint."""
        if not (os.name == "posix" and hasattr(os, "O_DIRECTORY")
                and os.open in os.supports_dir_fd
                and os.link in os.supports_dir_fd
                and os.unlink in os.supports_dir_fd):
            self.skipTest("Descriptor-relative POSIX publication required")
        from unittest.mock import patch

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
                self.handle.write(data[:3])
                raise OSError("simulated partial staging write")

            def __getattr__(self, name):
                return getattr(self.handle, name)

        def fail_write(fd, mode, *args, **kwargs):
            handle = original_fdopen(fd, mode, *args, **kwargs)
            if mode == "wb":
                return FailingWriter(handle)
            return handle

        with patch("ogde.m3_checkpoint.os.fdopen", side_effect=fail_write):
            with self.assertRaisesRegex(OSError, "partial staging write"):
                write_checkpoint(self.path, 11)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.glob(".ogde-checkpoint-*")), [])
        digest = write_checkpoint(self.path, 11)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 11)

    def test_staging_fsync_failure_does_not_publish(self):
        """A failed data sync must leave neither a checkpoint nor staging state."""
        if not (os.name == "posix" and hasattr(os, "O_DIRECTORY")
                and os.open in os.supports_dir_fd
                and os.link in os.supports_dir_fd
                and os.unlink in os.supports_dir_fd):
            self.skipTest("Descriptor-relative POSIX publication required")
        from unittest.mock import patch

        real_fsync = os.fsync
        calls = []

        def fail_staging_sync(fd):
            calls.append(os.fstat(fd).st_mode)
            if len(calls) == 1:
                raise OSError("simulated staging data sync failure")
            return real_fsync(fd)

        with patch("ogde.m3_checkpoint.os.fsync", side_effect=fail_staging_sync):
            with self.assertRaises(OSError):
                write_checkpoint(self.path, 10)
        self.assertEqual(len(calls), 1)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.glob(".ogde-checkpoint-*")), [])
        digest = write_checkpoint(self.path, 10)
        self.assertEqual(read_checkpoint(self.path, expected_digest=digest), 10)

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
