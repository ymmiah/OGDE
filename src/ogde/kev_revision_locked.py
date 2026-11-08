"""POSIX cooperative locking for signed KEV revision state acceptance.

All state writers must use this wrapper for concurrency safety.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .core import SecurityError
from .kev_revision_state import accept_kev_attestation, load_kev_revision_state
from .kev_revision_checkpoint import create_kev_revision_checkpoint, verify_kev_revision_checkpoint
from .kev_state_path_guard import validate_kev_state_path


def accept_kev_attestation_locked(snapshot: object, attestation: object, *,
                                  state_path: str | Path, trusted_public_pem: bytes,
                                  expected_signer: str, as_of: str,
                                  checkpoint: object | None = None) -> dict:
    """Serialise verification and state updates under a stable sidecar lock.

    When supplied, the independently retained checkpoint must match current
    state before acceptance. Return the new checkpoint for external anchoring.
    Without an external checkpoint, local filesystem rollback is undetectable.
    """
    try:
        import fcntl
    except ImportError as exc:
        raise SecurityError("POSIX advisory locks unavailable") from exc
    if not hasattr(os, "O_NOFOLLOW"):
        raise SecurityError("Secure no-follow lock opening unavailable")
    # Reject symlinked ancestors before creating/opening the sidecar lock.
    # State validation alone occurs too late to prevent redirected lock creation.
    target = validate_kev_state_path(state_path)
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise SecurityError("Invalid revision state directory")
    lock = parent / (target.name + ".lock")
    if lock.is_symlink():
        raise SecurityError("Refusing revision lock symlink")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise SecurityError("Cannot securely open revision lock") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise SecurityError("Revision lock must be a private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if checkpoint is not None:
            verify_kev_revision_checkpoint(load_kev_revision_state(target), checkpoint)
        receipt = accept_kev_attestation(
            snapshot, attestation, state_path=target,
            trusted_public_pem=trusted_public_pem,
            expected_signer=expected_signer, as_of=as_of
        )
        new_checkpoint = create_kev_revision_checkpoint(load_kev_revision_state(target))
        return {**receipt, "revision_checkpoint": new_checkpoint,
                "previous_checkpoint_verified": checkpoint is not None}
    finally:
        os.close(fd)
