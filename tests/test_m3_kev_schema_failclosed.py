"""Synthetic, offline fail-closed checks for locally pinned KEV snapshots.

A matching digest proves only byte-equivalent canonical content, not CISA
publisher identity, freshness, or authority to perform a response.
"""
import hashlib
import unittest

from ogde.core import SecurityError, canonical
from ogde.kev_ingest import ingest_kev_snapshot


def _ingest(rows):
    document = {"vulnerabilities": rows}
    digest = hashlib.sha256(canonical(document)).hexdigest()
    return ingest_kev_snapshot(document, expected_sha256=digest)


class KEVSchemaFailClosedTests(unittest.TestCase):
    def test_duplicate_cve_rejected_despite_matching_digest(self):
        row = {"cveID": "CVE-2026-12345", "dateAdded": "2026-11-01"}
        with self.assertRaisesRegex(SecurityError, "Duplicate KEV CVE"):
            _ingest([row, dict(row)])

    def test_malformed_cve_rejected_despite_matching_digest(self):
        for value in ("CVE-2026-1", "cve-2026-12345", "CVE-2026-12345\n", 12345):
            with self.subTest(value=value):
                with self.assertRaises(SecurityError):
                    _ingest([{"cveID": value, "dateAdded": "2026-11-01"}])

    def test_missing_or_non_string_date_rejected(self):
        for row in (
            {"cveID": "CVE-2026-12345"},
            {"cveID": "CVE-2026-12345", "dateAdded": None},
            {"cveID": "CVE-2026-12345", "dateAdded": 20261101},
        ):
            with self.subTest(row=row):
                with self.assertRaises(SecurityError):
                    _ingest([row])

    def test_valid_local_snapshot_remains_untrusted(self):
        receipt = _ingest([{
            "cveID": "CVE-2026-12345",
            "dateAdded": "2026-11-01",
            "knownRansomwareCampaignUse": "Known",
        }])
        self.assertEqual(receipt["kev_cves"], ["CVE-2026-12345"])
        self.assertEqual(receipt["entry_count"], 1)
        self.assertIs(receipt["integrity_verified"], True)
        self.assertIs(receipt["publisher_authenticated"], False)
        self.assertEqual(receipt["decision"], "human-review")


if __name__ == "__main__":
    unittest.main()
