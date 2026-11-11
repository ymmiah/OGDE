"""Offline M3 revision checkpoint primitives.

A local file is NOT an independent trust anchor. Callers must retain the
returned SHA-256 checkpoint outside the writable state directory and supply
it on every subsequent read. No publisher trust is granted here.
"""
from __future__ import annotations

import hashlib
import json
import os
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


def read_checkpoint(path: str | Path, *, expected_digest: str) -> int:
    """Reject missing, altered, noncanonical or oversized checkpoint files."""
    if not isinstance(expected_digest, str) or len(expected_digest) != 64 or any(
        c not in "0123456789abcdef" for c in expected_digest
    ):
        raise SecurityError("Independent checkpoint digest required")
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise SecurityError("Checkpoint missing or unsafe")
    if os.name == "posix" and p.stat().st_mode & 0o077:
        raise SecurityError("Checkpoint permissions are too broad")
    with p.open("rb") as handle:
        raw = handle.read(_MAX_STATE_BYTES + 1)
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
    fd, tmp = tempfile.mkstemp(prefix=".ogde-checkpoint-", dir=p.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600) if hasattr(os, "fchmod") else None
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        # Exclusive creation prevents accidental overwrite. This is not a
        # concurrency-safe transaction across independently running writers.
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
