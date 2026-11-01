"""Read-only CISA KEV snapshot ingestion with out-of-band digest pinning.

No network calls. A digest is an integrity check, not publisher authentication.
"""
from __future__ import annotations

import hashlib
import re
from datetime import date
from pathlib import Path

from .core import SecurityError, read_json, canonical
from .kev import kev_index

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def ingest_kev_snapshot(data: object, *, expected_sha256: str) -> dict:
    """Validate a local KEV snapshot and return a human-review-only receipt."""
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise SecurityError("Expected SHA-256 must be lowercase 64-character hex")
    if not isinstance(data, dict):
        raise SecurityError("KEV snapshot must be an object")
    # Embedded hashes or URLs cannot serve as independent trust anchors.
    actual = hashlib.sha256(canonical(data)).hexdigest()
    if actual != expected_sha256:
        raise SecurityError("KEV snapshot digest mismatch")
    entries = kev_index(data)
    for cve, entry in entries.items():
        date_added = entry["date_added"]
        if date_added is None:
            raise SecurityError("Missing KEV dateAdded")
        try:
            parsed = date.fromisoformat(date_added)
        except ValueError as exc:
            raise SecurityError("Invalid KEV dateAdded") from exc
        if parsed.isoformat() != date_added:
            raise SecurityError("KEV dateAdded must be YYYY-MM-DD")
    return {
        "kind": "ogde-kev-ingestion-receipt", "digest_sha256": actual,
        "entry_count": len(entries), "integrity_verified": True,
        "publisher_authenticated": False, "decision": "human-review",
        "kev_cves": sorted(entries),
        "limitations": [
            "SHA-256 equality does not authenticate CISA or establish feed freshness.",
            "KEV listing does not prove a local asset is vulnerable or compromised.",
        ],
    }


def ingest_kev_file(path: str | Path, *, expected_sha256: str) -> dict:
    return ingest_kev_snapshot(read_json(path), expected_sha256=expected_sha256)
