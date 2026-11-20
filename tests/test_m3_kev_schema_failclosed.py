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

    def test_invalid_calendar_and_noncanonical_dates_rejected(self):
        for value in ("2026-02-30", "2026-13-01", "2026-11-1", "20261101", "2026-11-01T00:00:00"):
            with self.subTest(date_added=value):
                with self.assertRaises(SecurityError):
                    _ingest([{"cveID": "CVE-2026-12345", "dateAdded": value}])

    def test_non_object_rows_rejected_with_matching_digest(self):
        for row in (None, "CVE-2026-12345", [], 42):
            with self.subTest(row=row):
                with self.assertRaisesRegex(SecurityError, "Malformed KEV vulnerability"):
                    _ingest([row])

    def test_entry_limit_rejected_with_matching_digest(self):
        row = {"cveID": "CVE-2026-12345", "dateAdded": "2026-11-01"}
        with self.assertRaisesRegex(SecurityError, "exceeds entry limit"):
            _ingest([row] * 20001)

    def test_incorrect_or_malformed_external_digest_rejected(self):
        document = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-11-01"}]}
        valid = hashlib.sha256(canonical(document)).hexdigest()
        for supplied in (None, 123, "", valid.upper(), valid[:-1], "0" * 64):
            with self.subTest(expected_sha256=supplied):
                with self.assertRaises(SecurityError):
                    ingest_kev_snapshot(document, expected_sha256=supplied)

    def test_embedded_digest_cannot_override_independent_pin(self):
        document = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-11-01"}]}
        independent_pin = hashlib.sha256(canonical(document)).hexdigest()
        document["sha256"] = hashlib.sha256(canonical(document)).hexdigest()
        with self.assertRaisesRegex(SecurityError, "digest mismatch"):
            ingest_kev_snapshot(document, expected_sha256=independent_pin)

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
