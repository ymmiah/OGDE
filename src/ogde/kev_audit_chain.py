"""Deterministic offline audit-chain verification; no signatures or timestamps."""
from __future__ import annotations
import hashlib
import re
from .core import SecurityError, canonical

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MAX = 10000


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def append_audit_record(chain: object, manifest: object) -> list[dict]:
    """Append a validated manifest to an in-memory, hash-linked audit chain."""
    previous = verify_audit_chain(chain)
    if not isinstance(manifest, dict) or manifest.get("kind") != "ogde-kev-review-audit":
        raise SecurityError("KEV audit manifest required")
    digest = manifest.get("manifest_sha256")
    if not _sha(digest):
        raise SecurityError("Invalid audit manifest digest")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if hashlib.sha256(canonical(body)).hexdigest() != digest:
        raise SecurityError("Tampered audit manifest")
    if len(previous) >= _MAX:
        raise SecurityError("Audit chain exceeds record limit")
    prev = previous[-1]["record_sha256"] if previous else None
    entry = {"sequence": len(previous) + 1, "previous_sha256": prev, "manifest": manifest}
    return [*previous, {**entry, "record_sha256": hashlib.sha256(canonical(entry)).hexdigest()}]


def verify_audit_chain(chain: object) -> list[dict]:
    """Verify every link and manifest; return a defensive copy on success."""
    if not isinstance(chain, list) or len(chain) > _MAX:
        raise SecurityError("Invalid audit chain")
    verified = []
    previous = None
    for position, record in enumerate(chain, 1):
        if not isinstance(record, dict) or set(record) != {"sequence", "previous_sha256", "manifest", "record_sha256"}:
            raise SecurityError("Invalid audit record schema")
        if type(record["sequence"]) is not int or record["sequence"] != position:
            raise SecurityError("Audit sequence mismatch")
        if record["previous_sha256"] != previous:
            raise SecurityError("Broken audit chain link")
        manifest = record["manifest"]
        if not isinstance(manifest, dict) or manifest.get("kind") != "ogde-kev-review-audit" or not _sha(manifest.get("manifest_sha256")):
            raise SecurityError("Invalid audit manifest")
        body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
        if hashlib.sha256(canonical(body)).hexdigest() != manifest["manifest_sha256"]:
            raise SecurityError("Audit manifest digest mismatch")
        if not _sha(record["record_sha256"]):
            raise SecurityError("Invalid audit record digest")
        entry = {"sequence": position, "previous_sha256": previous, "manifest": manifest}
        if hashlib.sha256(canonical(entry)).hexdigest() != record["record_sha256"]:
            raise SecurityError("Audit record digest mismatch")
        previous = record["record_sha256"]
        verified.append({**entry, "record_sha256": previous})
    return verified
