"""Offline, explicit hash chaining for independently retained review records.

No persistence, networking, trusted timestamps, signing or remediation.
"""
from hashlib import sha256
from hmac import compare_digest
import json
import re

from .review_audit import verify_review_audit_record

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset(("schema", "sequence", "previous_sha256", "record", "entry_sha256"))


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def append_review_audit_entry(record, *, sequence, previous_sha256=None):
    """Construct a chained entry. Caller must anchor and retain it independently."""
    if not verify_review_audit_record(record):
        raise ValueError("invalid review audit record")
    if type(sequence) is not int or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")
    if sequence == 0:
        if previous_sha256 is not None:
            raise ValueError("genesis must not have a previous hash")
    elif type(previous_sha256) is not str or not _HEX.fullmatch(previous_sha256):
        raise ValueError("non-genesis entry requires a lowercase SHA-256 hash")
    payload = {"schema": "ogde.review_audit_chain.v1", "sequence": sequence,
               "previous_sha256": previous_sha256, "record": dict(record)}
    payload["entry_sha256"] = sha256(_canonical(payload)).hexdigest()
    return payload


def verify_review_audit_chain(entries, *, expected_head_sha256=None):
    """Verify contiguous sequence and links; optional external head detects rollback."""
    if type(entries) is not list or not entries:
        return False
    previous = None
    for index, entry in enumerate(entries):
        if type(entry) is not dict or entry.keys() != _FIELDS:
            return False
        digest = entry.get("entry_sha256")
        if type(digest) is not str or not _HEX.fullmatch(digest):
            return False
        try:
            rebuilt = append_review_audit_entry(entry["record"], sequence=index,
                                                previous_sha256=previous)
        except (TypeError, ValueError, OverflowError):
            return False
        if not compare_digest(rebuilt["entry_sha256"], digest):
            return False
        if entry["schema"] != rebuilt["schema"] or entry["sequence"] != index:
            return False
        if entry["previous_sha256"] != previous:
            return False
        previous = digest
    if expected_head_sha256 is not None:
        if type(expected_head_sha256) is not str or not _HEX.fullmatch(expected_head_sha256):
            return False
        if not compare_digest(previous, expected_head_sha256):
            return False
    return True
