"""Private, fail-closed local revision state for signed KEV attestations.

Single-writer API. Keep state backups under an independent trust boundary.
"""
from __future__ import annotations
import os
import re
import stat
import tempfile
from pathlib import Path
from .core import MAX_JSON_BYTES, SecurityError, canonical
from .localio import load_json_file
from .kev_attestation import verify_kev_attestation
from .kev_state_path_guard import validate_kev_state_path

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_EMPTY = {"schema_version": 1, "kind": "ogde-kev-revision-state", "signers": {}}


def _validate(state: object) -> dict:
    if not isinstance(state, dict) or set(state) != {"schema_version", "kind", "signers"}:
        raise SecurityError("Invalid KEV revision state")
    if type(state["schema_version"]) is not int or state["schema_version"] != 1 or state["kind"] != _EMPTY["kind"]:
        raise SecurityError("Unsupported KEV revision state")
    signers = state["signers"]
    if not isinstance(signers, dict) or len(signers) > 1000:
        raise SecurityError("Invalid signer registry")
    for signer, record in signers.items():
        if not isinstance(signer, str) or not signer or len(signer) > 100:
            raise SecurityError("Invalid signer ID")
        if not isinstance(record, dict) or set(record) != {"revision", "key_id", "snapshot_sha256"}:
            raise SecurityError("Invalid signer revision record")
        if type(record["revision"]) is not int or not 1 <= record["revision"] <= 2**53:
            raise SecurityError("Invalid stored revision")
        if any(not isinstance(record[k], str) or not _SHA.fullmatch(record[k]) for k in ("key_id", "snapshot_sha256")):
            raise SecurityError("Invalid stored digest")
    return state


def load_kev_revision_state(path: str | Path) -> dict:
    target = validate_kev_state_path(path)
    if not target.exists():
        return {"schema_version": 1, "kind": _EMPTY["kind"], "signers": {}}
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1:
        raise SecurityError("Revision state must be a private, singly linked regular file")
    return _validate(load_json_file(target))


def accept_kev_attestation(snapshot: object, attestation: object, *,
                           state_path: str | Path, trusted_public_pem: bytes,
                           expected_signer: str, as_of: str) -> dict:
    """Verify signature then atomically record a strictly increasing revision.

    Requires a single trusted writer. Filesystem rollback and concurrent writers
    require separate protection; no publisher identity is inferred.
    """
    target = validate_kev_state_path(state_path)
    state = load_kev_revision_state(target)
    previous = state["signers"].get(expected_signer)
    revision = previous["revision"] if previous else 0
    receipt = verify_kev_attestation(
        snapshot, attestation, trusted_public_pem=trusted_public_pem,
        expected_signer=expected_signer, as_of=as_of, previous_revision=revision
    )
    if previous and receipt["signer_key_id"] != previous["key_id"]:
        raise SecurityError("Signer key rotation requires independent approval")
    updated = {"schema_version": 1, "kind": _EMPTY["kind"],
               "signers": {**state["signers"], expected_signer: {
                   "revision": receipt["revision"],
                   "key_id": receipt["signer_key_id"],
                   "snapshot_sha256": receipt["snapshot_digest_sha256"],
               }}}
    _validate(updated)
    data = canonical(updated) + b"\n"
    if len(data) > MAX_JSON_BYTES:
        raise SecurityError("Revision state exceeds size limit")
    name = None
    try:
        fd, name = tempfile.mkstemp(prefix=".ogde-kev-state-", dir=target.parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if target.is_symlink():
            raise SecurityError("Refusing revision state symlink")
        os.replace(name, target)
        name = None
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)
    return receipt
