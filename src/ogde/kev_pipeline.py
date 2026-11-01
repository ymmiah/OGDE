"""Offline KEV review pipeline: pinned ingestion, freshness and local reconciliation."""
from __future__ import annotations
from .core import SecurityError
from .kev_ingest import ingest_kev_snapshot
from .kev_freshness import assess_kev_freshness
from .kev_reconcile import reconcile_kev_findings


def review_kev_snapshot(snapshot: object, findings_document: object, *,
                        expected_sha256: str, snapshot_date: str, as_of: str,
                        max_age_days: int = 7) -> dict:
    """Fail closed on stale intelligence or inconsistent KEV claims.

    This is an offline evidence review, not a publisher-authentication mechanism.
    """
    receipt = ingest_kev_snapshot(snapshot, expected_sha256=expected_sha256)
    freshness = assess_kev_freshness(
        receipt, snapshot_date=snapshot_date, as_of=as_of, max_age_days=max_age_days
    )
    reconciliation = reconcile_kev_findings(findings_document, receipt)
    issues = []
    if freshness["freshness"] != "within-policy":
        issues.append("stale-snapshot")
    if reconciliation["inconsistent_signal_count"]:
        issues.append("inconsistent-kev-signals")
    return {
        "kind": "ogde-kev-review-pipeline",
        "digest_sha256": receipt["digest_sha256"],
        "freshness": freshness,
        "reconciliation": reconciliation,
        "review_status": "blocked" if issues else "requires-human-review",
        "issues": issues,
        "publisher_authenticated": False,
        "decision": "human-review",
        "limitations": [
            "Digest pinning does not authenticate the publisher.",
            "The operator-supplied snapshot date is not authenticated.",
            "A KEV match does not prove a local component is affected.",
        ],
    }
