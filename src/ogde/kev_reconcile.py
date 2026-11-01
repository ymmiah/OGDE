"""Read-only reconciliation of local findings against a pinned KEV receipt.

KEV presence is an intelligence signal, never proof an asset is affected.
"""
from __future__ import annotations

import re
from .core import SecurityError
from .finding import load_findings_document

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")


def reconcile_kev_findings(document: object, receipt: object) -> dict:
    """Return review-only annotations; never modify the supplied findings."""
    if not isinstance(receipt, dict) or receipt.get("kind") != "ogde-kev-ingestion-receipt":
        raise SecurityError("KEV ingestion receipt required")
    if receipt.get("integrity_verified") is not True or receipt.get("publisher_authenticated") is not False:
        raise SecurityError("Receipt must be integrity-checked and unauthenticated")
    digest = receipt.get("digest_sha256")
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise SecurityError("Invalid KEV receipt digest")
    cves = receipt.get("kev_cves")
    if not isinstance(cves, list) or len(cves) > 20000 or any(
        not isinstance(cve, str) or not _CVE.fullmatch(cve) for cve in cves
    ) or cves != sorted(set(cves)):
        raise SecurityError("Invalid or duplicate KEV CVE index")
    if type(receipt.get("entry_count")) is not int or receipt["entry_count"] != len(cves):
        raise SecurityError("KEV receipt count mismatch")
    findings = load_findings_document(document)
    index = set(cves)
    annotations = []
    for item in findings:
        vuln = item["vulnerability"]["id"]
        listed = vuln in index
        declared = item["signals"]["kev_listed"]
        annotations.append({
            "finding_id": item["finding_id"],
            "vulnerability_id": vuln,
            "kev_in_snapshot": listed,
            "declared_kev_signal": declared,
            "signal_consistent": listed == declared,
            "decision": "human-review",
        })
    return {
        "kind": "ogde-kev-local-reconciliation",
        "snapshot_digest_sha256": digest,
        "finding_count": len(annotations),
        "inconsistent_signal_count": sum(not row["signal_consistent"] for row in annotations),
        "annotations": annotations,
        "publisher_authenticated": False,
        "decision": "human-review",
        "limitations": [
            "KEV listing does not establish that the local component is affected.",
            "Absence from this snapshot does not prove a vulnerability is not exploited.",
            "Snapshot provenance, completeness and freshness are not authenticated here.",
        ],
    }
