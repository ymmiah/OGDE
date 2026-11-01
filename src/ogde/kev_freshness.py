"""Offline KEV freshness assessment; never grants publisher trust."""
from __future__ import annotations
from datetime import date
from .core import SecurityError


def assess_kev_freshness(receipt: dict, *, snapshot_date: str, as_of: str,
                         max_age_days: int = 7) -> dict:
    """Apply an operator-supplied freshness policy without network or side effects."""
    if not isinstance(receipt, dict) or receipt.get("kind") != "ogde-kev-ingestion-receipt":
        raise SecurityError("Validated KEV ingestion receipt required")
    if receipt.get("integrity_verified") is not True:
        raise SecurityError("Unverified KEV receipt")
    if receipt.get("publisher_authenticated") is not False:
        raise SecurityError("Publisher authentication must be assessed independently")
    if type(max_age_days) is not int or not 0 <= max_age_days <= 365:
        raise SecurityError("max_age_days must be an integer between 0 and 365")
    try:
        observed = date.fromisoformat(snapshot_date)
        today = date.fromisoformat(as_of)
        if observed.isoformat() != snapshot_date or today.isoformat() != as_of:
            raise ValueError("noncanonical date")
    except (ValueError, TypeError, AttributeError) as exc:
        raise SecurityError("Dates must use YYYY-MM-DD") from exc
    age = (today - observed).days
    if age < 0:
        raise SecurityError("Snapshot date cannot be in the future")
    return {
        "kind": "ogde-kev-freshness-assessment",
        "digest_sha256": receipt["digest_sha256"],
        "age_days": age,
        "max_age_days": max_age_days,
        "freshness": "within-policy" if age <= max_age_days else "stale",
        "publisher_authenticated": False,
        "decision": "human-review",
        "limitations": [
            "Snapshot date is supplied by the operator, not authenticated by this assessment.",
            "Within-policy age is not proof of publisher authenticity or feed completeness.",
        ],
    }
