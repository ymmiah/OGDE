"""Verify an audit chain extends an independently authenticated prior checkpoint."""
from hmac import compare_digest
from .review_audit_checkpoint import verify_review_audit_checkpoint


def verify_review_audit_continuity(entries, previous_checkpoint, current_checkpoint, *, require_advance=False):
    """Fail closed unless current chain retains the exact anchored previous prefix.

    Set require_advance=True for workflows that must reject replay/no-op updates.
    Both checkpoints must be authenticated independently by the caller.
    No I/O, signing, network access or trust-anchor management occurs here.
    """
    if type(require_advance) is not bool:
        return False
    if type(entries) is not list or type(previous_checkpoint) is not dict:
        return False
    if type(current_checkpoint) is not dict:
        return False
    prior_count = previous_checkpoint.get('entry_count')
    current_count = current_checkpoint.get('entry_count')
    if type(prior_count) is not int or type(current_count) is not int:
        return False
    if prior_count < 1 or current_count < prior_count or len(entries) != current_count:
        return False
    if require_advance and current_count == prior_count:
        return False
    if not verify_review_audit_checkpoint(entries, current_checkpoint):
        return False
    # Verify the complete prior prefix, not just the predecessor pointer.
    if not verify_review_audit_checkpoint(entries[:prior_count], previous_checkpoint):
        return False
    return compare_digest(entries[prior_count - 1]['entry_sha256'], previous_checkpoint['head_sha256'])
