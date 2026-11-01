"""Out-of-band audit-chain checkpoints for detecting later truncation or rewrites.

Store checkpoints separately from the chain, under an independent trust boundary.
"""
from __future__ import annotations

import hashlib
import re
from .core import SecurityError, canonical
from .kev_audit_chain import verify_audit_chain

_SHA = re.compile(r"[0-9a-f]{64}\Z")


def create_audit_checkpoint(chain: object) -> dict:
    """Summarise a verified nonempty chain without leaking local finding details."""
    records = verify_audit_chain(chain)
    if not records:
        raise SecurityError("Cannot checkpoint an empty chain")
    body = {
        "kind": "ogde-kev-audit-checkpoint",
        "schema_version": 1,
        "record_count": len(records),
        "head_sha256": records[-1]["record_sha256"],
    }
    return {**body, "checkpoint_sha256": hashlib.sha256(canonical(body)).hexdigest()}


def verify_audit_checkpoint(chain: object, checkpoint: object) -> bool:
    """Verify chain integrity and equality with an independently retained checkpoint."""
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        "kind", "schema_version", "record_count", "head_sha256", "checkpoint_sha256"
    }:
        raise SecurityError("Invalid checkpoint schema")
    if checkpoint["kind"] != "ogde-kev-audit-checkpoint" or type(checkpoint["schema_version"]) is not int or checkpoint["schema_version"] != 1:
        raise SecurityError("Unsupported checkpoint")
    if type(checkpoint["record_count"]) is not int or checkpoint["record_count"] < 1:
        raise SecurityError("Invalid checkpoint record count")
    if any(not isinstance(checkpoint[key], str) or not _SHA.fullmatch(checkpoint[key])
           for key in ("head_sha256", "checkpoint_sha256")):
        raise SecurityError("Invalid checkpoint digest")
    body = {key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"}
    if hashlib.sha256(canonical(body)).hexdigest() != checkpoint["checkpoint_sha256"]:
        raise SecurityError("Checkpoint content was modified")
    records = verify_audit_chain(chain)
    if len(records) != checkpoint["record_count"] or not records or records[-1]["record_sha256"] != checkpoint["head_sha256"]:
        raise SecurityError("Audit chain differs from checkpoint")
    return True
