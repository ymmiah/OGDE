"""Local audit snapshots with atomic replacement and fail-closed loading.

Not a multi-writer database; caller must provide exclusive writer coordination.
"""
from __future__ import annotations
import json
import os
import stat
import tempfile
from pathlib import Path
from .core import MAX_JSON_BYTES, SecurityError, canonical
from .kev_audit_chain import verify_audit_chain
from .kev_checkpoint import verify_audit_checkpoint
from .localio import load_json_file


def _parent(path: Path) -> Path:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise SecurityError("Audit parent must be an existing real directory")
    return parent


def load_audit_snapshot(path: str | Path, *, checkpoint: object | None = None) -> list[dict]:
    """Read a non-symlinked, integrity-checked local audit snapshot."""
    target = Path(path)
    _parent(target)
    try:
        info = target.lstat()
    except FileNotFoundError as exc:
        raise SecurityError("Audit snapshot does not exist") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise SecurityError("Audit snapshot must be a private regular file")
    chain = verify_audit_chain(load_json_file(target))
    if checkpoint is not None:
        verify_audit_checkpoint(chain, checkpoint)
    return chain


def save_audit_snapshot(path: str | Path, chain: object, *,
                        expected_head: str | None = None) -> None:
    """Atomically replace a private snapshot; never silently overwrite an existing chain.

    expected_head must equal the current head for updates. This is not a lock:
    concurrent writers still require external serialisation.
    """
    verified = verify_audit_chain(chain)
    target = Path(path)
    parent = _parent(target)
    if target.is_symlink():
        raise SecurityError("Refusing audit symlink target")
    if target.exists():
        current = load_audit_snapshot(target)
        head = current[-1]["record_sha256"] if current else None
        if expected_head is None or expected_head != head:
            raise SecurityError("Existing audit snapshot requires matching expected head")
        if len(verified) < len(current) or verified[:len(current)] != current:
            raise SecurityError("Audit snapshot updates must preserve existing history")
    elif expected_head is not None:
        raise SecurityError("Expected existing audit snapshot is missing")
    data = canonical(verified) + b"\n"
    if len(data) > MAX_JSON_BYTES:
        raise SecurityError("Audit snapshot exceeds size limit")
    temp_path = None
    try:
        fd, name = tempfile.mkstemp(prefix=".ogde-audit-", suffix=".tmp", dir=parent)
        temp_path = Path(name)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if target.is_symlink():
            raise SecurityError("Refusing audit symlink target")
        os.replace(temp_path, target)
        temp_path = None
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
