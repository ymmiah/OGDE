"""Offline advisory evidence gate. Never fetches remote resources or executes advice."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from .core import SecurityError, read_json, canonical

_SHA = re.compile(r"[0-9a-f]{64}\Z")


def verify_local_evidence(document: object, *, expected_sha256: str, source_path: str | Path) -> dict:
    """Check locally supplied evidence against an independently provided digest.

    This is integrity checking, not publisher authentication. Callers must verify
    the digest's origin out of band before treating a record as trusted.
    """
    if not isinstance(expected_sha256, str) or not _SHA.fullmatch(expected_sha256):
        raise SecurityError("Expected SHA-256 must be 64 lowercase hexadecimal characters")
    if not isinstance(document, dict) or set(document) != {"schema_version", "source", "records"}:
        raise SecurityError("Unexpected evidence document structure")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise SecurityError("Unsupported evidence schema")
    if not isinstance(document["source"], str) or not 1 <= len(document["source"]) <= 120:
        raise SecurityError("Invalid evidence source")
    records = document["records"]
    if not isinstance(records, list) or len(records) > 5000:
        raise SecurityError("Invalid evidence record count")
    seen = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", "digest_sha256"}:
            raise SecurityError("Unexpected evidence record")
        rid, digest = record["id"], record["digest_sha256"]
        if not isinstance(rid, str) or not 1 <= len(rid) <= 150 or any(ord(c) < 33 or ord(c) > 126 for c in rid):
            raise SecurityError("Invalid record identifier")
        if rid in seen:
            raise SecurityError("Duplicate evidence record")
        seen.add(rid)
        if not isinstance(digest, str) or not _SHA.fullmatch(digest):
            raise SecurityError("Invalid record digest")
    actual = hashlib.sha256(canonical(document)).hexdigest()
    if actual != expected_sha256:
        raise SecurityError("Evidence digest mismatch")
    return {"verified_integrity": True, "publisher_authenticated": False,
            "source_path": str(source_path), "digest_sha256": actual,
            "record_count": len(records), "decision": "human-review"}


def verify_local_evidence_file(path: str | Path, *, expected_sha256: str) -> dict:
    return verify_local_evidence(read_json(path), expected_sha256=expected_sha256, source_path=path)
