"""Offline M3 revision checkpoint primitives.

A local file is NOT an independent trust anchor. Callers must retain the
returned SHA-256 checkpoint outside the writable state directory and supply
it on every subsequent read. No publisher trust is granted here.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from .core import SecurityError

_MAX_REVISION = 2**53
_MAX_STATE_BYTES = 4096


def _encode(revision: int) -> bytes:
    if type(revision) is not int or not 1 <= revision <= _MAX_REVISION:
        raise SecurityError("Invalid checkpoint revision")
    return (json.dumps({"schema_version": 1, "revision": revision},
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def checkpoint_digest(revision: int) -> str:
    """Digest for independent, out-of-band retention; not a signature."""
    return hashlib.sha256(_encode(revision)).hexdigest()



def _open_parent_chain(path: Path) -> int:
    """Open each directory from the filesystem root without following aliases.

    The returned descriptor is the parent inode used for subsequent operations.
    Callers own it and must close it. POSIX only; requires dir_fd support.
    """
    absolute = path.absolute()
    parts = absolute.parts
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(parts[0], flags)
    try:
        for part in parts[1:]:
            if part in ("", ".", ".."):
                raise SecurityError("Unsafe checkpoint ancestor component")
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise

def read_checkpoint(path: str | Path, *, expected_digest: str) -> int:
    """Reject missing, altered, noncanonical or oversized checkpoint files."""
    if not isinstance(expected_digest, str) or len(expected_digest) != 64 or any(
        c not in "0123456789abcdef" for c in expected_digest
    ):
        raise SecurityError("Independent checkpoint digest required")
    p = Path(path)
    # The independently supplied digest protects contents, but the containing
    # directory must also be owner-controlled to prevent local path swaps.
    try:
        parent = p.parent.lstat()
    except OSError as exc:
        raise SecurityError("Checkpoint directory missing or unsafe") from exc
    if not stat.S_ISDIR(parent.st_mode) or (
        os.name == "posix" and (
            parent.st_uid != os.geteuid() or parent.st_mode & 0o022
        )
    ):
        raise SecurityError("Checkpoint directory must be owner-controlled")
    # An intermediate symlink can redirect the path even when its immediate
    # parent is a genuine owner-controlled directory. Reject such aliases.
    for ancestor in p.parent.parents:
        try:
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                raise SecurityError("Checkpoint ancestor symlink is unsafe")
        except OSError as exc:
            raise SecurityError("Checkpoint ancestor missing or unsafe") from exc
    # Open the inode first: path-based checks followed by open() permit a
    # symlink swap between validation and reading.
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    # On POSIX, bind the final open to a verified directory descriptor.
    # This prevents a parent path replacement between validation and opening
    # the checkpoint from silently redirecting the final file lookup.
    parent_fd = -1
    try:
        if os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
            parent_fd = _open_parent_chain(p.parent)
            opened_parent = os.fstat(parent_fd)
            if (not stat.S_ISDIR(opened_parent.st_mode)
                    or opened_parent.st_dev != parent.st_dev
                    or opened_parent.st_ino != parent.st_ino
                    or opened_parent.st_uid != os.geteuid()
                    or opened_parent.st_mode & 0o022):
                raise SecurityError("Checkpoint directory changed or unsafe")
            fd = os.open(p.name, flags, dir_fd=parent_fd)
        else:
            fd = os.open(p, flags)
    except OSError as exc:
        raise SecurityError("Checkpoint missing or unsafe") from exc
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
    try:
        # fstat before fdopen: Python rejects directory descriptors during
        # fdopen(), and all unsafe inode types must fail as SecurityError.
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecurityError("Checkpoint missing or unsafe")
        # The checkpoint inode must belong to the verifying local user.
        if os.name == "posix" and metadata.st_uid != os.geteuid():
            raise SecurityError("Checkpoint owner is not the current user")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            if not stat.S_ISREG(metadata.st_mode):
                raise SecurityError("Checkpoint missing or unsafe")
            if os.name == "posix" and metadata.st_mode & 0o077:
                raise SecurityError("Checkpoint permissions are too broad")
            if metadata.st_nlink != 1:
                raise SecurityError("Checkpoint hard links are unsafe")
            if metadata.st_size > _MAX_STATE_BYTES:
                raise SecurityError("Checkpoint integrity mismatch")
            raw = handle.read(_MAX_STATE_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > _MAX_STATE_BYTES or hashlib.sha256(raw).hexdigest() != expected_digest:
        raise SecurityError("Checkpoint integrity mismatch")
    try:
        obj = json.loads(raw)
        if type(obj) is not dict or set(obj) != {"schema_version", "revision"}:
            raise ValueError("Unexpected checkpoint schema")
        if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
            raise ValueError("Unexpected schema version")
        revision = obj["revision"]
        if raw != _encode(revision):
            raise ValueError("Noncanonical checkpoint")
        return revision
    except (ValueError, TypeError, UnicodeError) as exc:
        raise SecurityError("Invalid checkpoint contents") from exc


def write_checkpoint(path: str | Path, revision: int, *,
                     previous_revision: int = 0) -> str:
    """Atomically write a higher revision; return digest for external retention.

    Only suitable for an owner-controlled, single-writer directory. This
    function does not lock concurrent writers, validate publisher freshness,
    or independently protect the returned digest. Never use it as an
    automatic trust-promotion mechanism.
    """
    if type(revision) is not int or type(previous_revision) is not int or not 0 <= previous_revision < revision:
        raise SecurityError("Checkpoint rollback or invalid previous revision")
    raw = _encode(revision)
    p = Path(path)
    if p.is_symlink() or p.exists():
        raise SecurityError("Refusing to overwrite checkpoint; archive and verify previous state first")
    if not p.parent.is_dir() or p.parent.is_symlink():
        raise SecurityError("Checkpoint directory missing or unsafe")
    # A checkpoint cannot be reliably owned by a single writer when other
    # local users can replace its directory entries. The external digest
    # remains mandatory even when this local directory check passes.
    try:
        directory = p.parent.stat()
    except OSError as exc:
        raise SecurityError("Checkpoint directory missing or unsafe") from exc
    if os.name == "posix" and (
        directory.st_uid != os.geteuid() or directory.st_mode & 0o022
    ):
        raise SecurityError("Checkpoint directory must be owner-controlled")
    # Reject redirection through an ancestor, not just the immediate parent.
    # POSIX publication additionally traverses ancestors by descriptor.
    for ancestor in p.parent.parents:
        try:
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                raise SecurityError("Checkpoint ancestor symlink is unsafe")
        except OSError as exc:
            raise SecurityError("Checkpoint ancestor missing or unsafe") from exc
    # Validate the parent through the same descriptor used for publication.
    # A separate validation open would introduce an unnecessary path-reopen
    # window before the descriptor-relative staging transaction.
    # POSIX publication uses a single verified parent descriptor for staging,
    # exclusive linking, cleanup and durability. Do not reopen the path.
    if os.name == "posix" and all(
        hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_EXCL")
    ) and os.open in os.supports_dir_fd and os.link in os.supports_dir_fd and os.unlink in os.supports_dir_fd:
        import secrets
        try:
            parent_fd = _open_parent_chain(p.parent)
        except OSError as exc:
            raise SecurityError("Checkpoint directory missing or unsafe") from exc
        try:
            opened = os.fstat(parent_fd)
            if (not stat.S_ISDIR(opened.st_mode)
                    or opened.st_dev != directory.st_dev
                    or opened.st_ino != directory.st_ino
                    or opened.st_uid != os.geteuid()
                    or opened.st_mode & 0o022):
                raise SecurityError("Checkpoint directory changed or unsafe")
            tmp_name = ".ogde-checkpoint-" + secrets.token_hex(16)
            fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent_fd)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                # The target must not be replaced or overwritten.
                os.link(tmp_name, p.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            finally:
                # Remove staging state before syncing the directory so a
                # successful return covers both publication and cleanup.
                os.unlink(tmp_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    else:
        # Non-POSIX compatibility path; no claim of race-free publication.
        fd, tmp = tempfile.mkstemp(prefix=".ogde-checkpoint-", dir=p.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600) if hasattr(os, "fchmod") else None
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(tmp, p)
            if hasattr(os, "O_DIRECTORY"):
                directory_fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            os.unlink(tmp)
    return hashlib.sha256(raw).hexdigest()
