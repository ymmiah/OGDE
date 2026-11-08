"""Minimal, privacy-preserving audit records for offline review decisions.

This helper never accepts inventory, advisory content, paths or free-text notes.
It does not write files, send network requests or authorise remediation.
"""
from datetime import datetime
from hashlib import sha256
import json
import re

_EVENTS = frozenset({'evidence_review', 'revision_acceptance', 'checkpoint_verification'})
_OUTCOMES = frozenset({'accepted', 'rejected', 'requires_review'})
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def make_review_audit_record(*, event, outcome, occurred_at, evidence_sha256=None):
    """Return an allowlisted, deterministic audit record; fail closed on bad input."""
    if type(event) is not str or event not in _EVENTS:
        raise ValueError('unsupported audit event')
    if type(outcome) is not str or outcome not in _OUTCOMES:
        raise ValueError('unsupported audit outcome')
    if type(occurred_at) is not str:
        raise ValueError('occurred_at must be an ISO-8601 timestamp with timezone')
    try:
        stamp = datetime.fromisoformat(occurred_at.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('invalid occurred_at') from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError('occurred_at must have a timezone')
    if evidence_sha256 is not None and (type(evidence_sha256) is not str or not _DIGEST.fullmatch(evidence_sha256)):
        raise ValueError('evidence_sha256 must be lowercase hex SHA-256')
    record = {'schema': 'ogde.review_audit.v1', 'event': event, 'outcome': outcome,
              'occurred_at': stamp.isoformat(timespec='microseconds'),
              'evidence_sha256': evidence_sha256}
    canonical = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    record['record_sha256'] = sha256(canonical.encode('ascii')).hexdigest()
    return record


def verify_review_audit_record(record):
    """Validate the complete v1 schema and checksum without trusting record contents.

    Returns bool. A checksum alone cannot authenticate an external publisher.
    """
    from hmac import compare_digest

    required = frozenset({'schema', 'event', 'outcome', 'occurred_at',
                          'evidence_sha256', 'record_sha256'})
    if type(record) is not dict or record.keys() != required:
        return False
    if record['schema'] != 'ogde.review_audit.v1':
        return False
    checksum = record['record_sha256']
    if type(checksum) is not str or not _DIGEST.fullmatch(checksum):
        return False
    try:
        rebuilt = make_review_audit_record(
            event=record['event'], outcome=record['outcome'],
            occurred_at=record['occurred_at'], evidence_sha256=record['evidence_sha256'])
    except (ValueError, TypeError, OverflowError):
        return False
    # Reject non-canonical timestamps and implicit normalisation.
    if rebuilt['occurred_at'] != record['occurred_at']:
        return False
    return compare_digest(rebuilt['record_sha256'], checksum)
