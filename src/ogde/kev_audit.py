"""Deterministic, privacy-minimised audit manifest for offline KEV reviews.

The manifest is a digest-linked record, not a signature or trusted timestamp.
"""
from __future__ import annotations

import hashlib
import re
from .core import SecurityError, canonical

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED = {"stale-snapshot", "inconsistent-kev-signals"}


def build_kev_audit_manifest(review: object) -> dict:
    """Validate a review result and create a reproducible, non-sensitive manifest."""
    if not isinstance(review, dict) or review.get("kind") != "ogde-kev-review-pipeline":
        raise SecurityError("KEV pipeline review required")
    digest = review.get("digest_sha256")
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise SecurityError("Invalid review digest")
    if review.get("publisher_authenticated") is not False or review.get("decision") != "human-review":
        raise SecurityError("Invalid trust or decision claims")
    issues = review.get("issues")
    if not isinstance(issues, list) or any(type(i) is not str or i not in _ALLOWED for i in issues):
        raise SecurityError("Invalid review issues")
    if len(issues) != len(set(issues)):
        raise SecurityError("Review issues must be unique")
    status = review.get("review_status")
    if status != ("blocked" if issues else "requires-human-review"):
        raise SecurityError("Review status contradicts issues")
    freshness = review.get("freshness")
    reconciliation = review.get("reconciliation")
    if not isinstance(freshness, dict) or not isinstance(reconciliation, dict):
        raise SecurityError("Missing pipeline evidence")
    if freshness.get("digest_sha256") != digest or reconciliation.get("snapshot_digest_sha256") != digest:
        raise SecurityError("Pipeline evidence digest mismatch")
    if freshness.get("kind") != "ogde-kev-freshness-assessment" or reconciliation.get("kind") != "ogde-kev-local-reconciliation":
        raise SecurityError("Unexpected evidence type")
    age = freshness.get("age_days")
    limit = freshness.get("max_age_days")
    if type(age) is not int or type(limit) is not int or not 0 <= age <= 365000 or not 0 <= limit <= 365:
        raise SecurityError("Invalid freshness metrics")
    expected_freshness = "within-policy" if age <= limit else "stale"
    if freshness.get("freshness") != expected_freshness:
        raise SecurityError("Contradictory freshness")
    count = reconciliation.get("finding_count")
    inconsistent = reconciliation.get("inconsistent_signal_count")
    annotations = reconciliation.get("annotations")
    if type(count) is not int or type(inconsistent) is not int or not 0 <= inconsistent <= count <= 2000:
        raise SecurityError("Invalid reconciliation metrics")
    if not isinstance(annotations, list) or len(annotations) != count:
        raise SecurityError("Reconciliation annotations count mismatch")
    if any(not isinstance(row, dict) or type(row.get("signal_consistent")) is not bool for row in annotations):
        raise SecurityError("Invalid reconciliation annotations")
    if sum(not row["signal_consistent"] for row in annotations) != inconsistent:
        raise SecurityError("Reconciliation inconsistencies do not match annotations")
    expected_issues = (["stale-snapshot"] if age > limit else []) + (["inconsistent-kev-signals"] if inconsistent else [])
    if issues != expected_issues:
        raise SecurityError("Review issues contradict evidence")
    manifest = {
        "schema_version": 1,
        "kind": "ogde-kev-review-audit",
        "snapshot_digest_sha256": digest,
        "review_status": status,
        "issues": issues,
        "age_days": age,
        "max_age_days": limit,
        "finding_count": count,
        "inconsistent_signal_count": inconsistent,
        "decision": "human-review",
        "publisher_authenticated": False,
    }
    return {**manifest, "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest()}
