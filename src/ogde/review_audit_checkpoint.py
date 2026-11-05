"""Validate independently retained audit-chain checkpoints, without I/O or trust claims."""
import re
from .review_audit_chain import verify_review_audit_chain

_HEX = re.compile(r'[0-9a-f]{64}\Z')
_FIELDS = frozenset(('schema', 'entry_count', 'head_sha256'))


def make_review_audit_checkpoint(entries):
    """Build a checkpoint for separate, owner-controlled authenticated retention."""
    if not verify_review_audit_chain(entries):
        raise ValueError('invalid audit chain')
    return {'schema': 'ogde.review_audit_checkpoint.v1',
            'entry_count': len(entries), 'head_sha256': entries[-1]['entry_sha256']}


def verify_review_audit_checkpoint(entries, checkpoint):
    """Compare chain to checkpoint; caller must authenticate checkpoint independently."""
    if type(checkpoint) is not dict or checkpoint.keys() != _FIELDS:
        return False
    if checkpoint['schema'] != 'ogde.review_audit_checkpoint.v1':
        return False
    count = checkpoint['entry_count']
    head = checkpoint['head_sha256']
    if type(count) is not int or count < 1:
        return False
    if type(head) is not str or not _HEX.fullmatch(head):
        return False
    if type(entries) is not list or len(entries) != count:
        return False
    return verify_review_audit_chain(entries, expected_head_sha256=head)
