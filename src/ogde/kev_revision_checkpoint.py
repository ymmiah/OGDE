"""Independently retained checkpoints for offline KEV revision state.

The checkpoint is an unkeyed digest, not a signature or trusted timestamp.
"""
from __future__ import annotations
import hashlib
import re
from .core import SecurityError, canonical
from .kev_revision_state import _validate

_SHA = re.compile(r"[0-9a-f]{64}\Z")


def create_kev_revision_checkpoint(state: object) -> dict:
    """Summarise a validated state without exposing signer-specific metadata."""
    verified = _validate(state)
    body = {
        "kind": "ogde-kev-revision-checkpoint",
        "schema_version": 1,
        "state_sha256": hashlib.sha256(canonical(verified)).hexdigest(),
        "signer_count": len(verified["signers"]),
    }
    return {**body, "checkpoint_sha256": hashlib.sha256(canonical(body)).hexdigest()}


def verify_kev_revision_checkpoint(state: object, checkpoint: object) -> bool:
    """Fail closed if the local state differs from an out-of-band checkpoint."""
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        "kind", "schema_version", "state_sha256", "signer_count", "checkpoint_sha256"
    }:
        raise SecurityError("Invalid revision checkpoint schema")
    if checkpoint["kind"] != "ogde-kev-revision-checkpoint" or type(checkpoint["schema_version"]) is not int or checkpoint["schema_version"] != 1:
        raise SecurityError("Unsupported revision checkpoint")
    if type(checkpoint["signer_count"]) is not int or not 0 <= checkpoint["signer_count"] <= 1000:
        raise SecurityError("Invalid checkpoint signer count")
    if any(not isinstance(checkpoint[k], str) or not _SHA.fullmatch(checkpoint[k])
           for k in ("state_sha256", "checkpoint_sha256")):
        raise SecurityError("Invalid checkpoint digest")
    body = {k: v for k, v in checkpoint.items() if k != "checkpoint_sha256"}
    if hashlib.sha256(canonical(body)).hexdigest() != checkpoint["checkpoint_sha256"]:
        raise SecurityError("Modified revision checkpoint")
    actual = create_kev_revision_checkpoint(state)
    if actual != checkpoint:
        raise SecurityError("Revision state differs from independently retained checkpoint")
    return True
