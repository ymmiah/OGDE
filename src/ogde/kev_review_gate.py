"""Fail-closed, review-gated acceptance of offline signed KEV snapshots.

No intelligence is committed if freshness or reconciliation is blocked.
This is a local human-review evidence gate, not CISA authentication.
"""
from __future__ import annotations

import json
from pathlib import Path

from .core import SecurityError, canonical
from .kev_pipeline import review_kev_snapshot
from .kev_revision_locked import accept_kev_attestation_locked


def review_and_accept_signed_kev(
    snapshot: object, findings_document: object, attestation: object, *,
    state_path: str | Path, trusted_public_pem: bytes,
    expected_signer: str, snapshot_date: str, as_of: str,
    max_age_days: int = 7,
) -> dict:
    """Preflight review before advancing revision state under the POSIX lock.

    A blocked review never calls the state writer. A passing review still
    requires human approval before any consequential remediation.
    """
    # Freeze caller-owned inputs so a mutation between review and signature
    # verification cannot silently change what was reviewed.
    try:
        frozen_snapshot = json.loads(canonical(snapshot))
        frozen_findings = json.loads(canonical(findings_document))
        frozen_attestation = json.loads(canonical(attestation))
    except (ValueError, TypeError, RecursionError) as exc:
        raise SecurityError("Invalid signed KEV review inputs") from exc
    if not isinstance(frozen_attestation, dict) or not isinstance(frozen_attestation.get("statement"), dict):
        raise SecurityError("Invalid signed KEV attestation")
    digest = frozen_attestation["statement"].get("snapshot_sha256")
    review = review_kev_snapshot(
        frozen_snapshot, frozen_findings, expected_sha256=digest,
        snapshot_date=snapshot_date, as_of=as_of, max_age_days=max_age_days
    )
    if (not isinstance(review, dict)
            or review.get("review_status") != "requires-human-review"
            or type(review.get("issues")) is not list
            or review["issues"]):
        raise SecurityError("Blocked or malformed KEV review: revision state not advanced")
    # Check review/attestation agreement BEFORE any trusted-state write.
    # The post-write receipt check remains a defence-in-depth assertion.
    if not isinstance(digest, str) or review.get("digest_sha256") != digest:
        raise SecurityError("Review digest differs from signed attestation: state not advanced")
    receipt = accept_kev_attestation_locked(
        frozen_snapshot, frozen_attestation, state_path=state_path,
        trusted_public_pem=trusted_public_pem,
        expected_signer=expected_signer, as_of=as_of
    )
    if receipt["snapshot_digest_sha256"] != review["digest_sha256"]:
        raise SecurityError("Signed snapshot differs from reviewed snapshot")
    return {"review": review, "attestation": receipt, "decision": "human-review"}
