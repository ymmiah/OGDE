"""POSIX advisory-lock coordination for local KEV audit append operations.

All writers must use this API. Not safe against hostile filesystem owners.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .core import SecurityError
from .kev_audit_chain import append_audit_record
from .kev_store import load_audit_snapshot, save_audit_snapshot


def append_audit_locked(path: str | Path, manifest: object, *,
                        checkpoint: object | None = None) -> list[dict]:
    """Serialise cooperative writers and append a verified audit manifest.

    Uses a stable sidecar lock file rather than locking the atomically replaced
    snapshot inode. Only supported on POSIX systems with fcntl.flock.
    """
    try:
        import fcntl
    except ImportError as exc:
        raise SecurityError("POSIX advisory file locks are unavailable") from exc
    target = Path(path)
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise SecurityError("Audit directory must exist and not be a symlink")
    lock = parent / (target.name + ".lock")
    if lock.is_symlink():
        raise SecurityError("Refusing symlink audit lock")
    flags = os.O_CREAT | os.O_RDWR
    if not hasattr(os, "O_NOFOLLOW"):
        raise SecurityError("Secure no-follow lock opening is unavailable")
    flags |= os.O_NOFOLLOW
    try:
        fd = os.open(lock, flags, 0o600)
    except OSError as exc:
        raise SecurityError("Cannot securely open audit lock") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise SecurityError("Audit lock must be a private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if target.is_symlink():
            raise SecurityError("Refusing symlink audit snapshot")
        if target.exists():
            current = load_audit_snapshot(target, checkpoint=checkpoint)
            head = current[-1]["record_sha256"] if current else None
        else:
            if checkpoint is not None:
                raise SecurityError("Checkpoint provided but audit snapshot is missing")
            current, head = [], None
        updated = append_audit_record(current, manifest)
        save_audit_snapshot(target, updated, expected_head=head)
        return updated
    finally:
        os.close(fd)
