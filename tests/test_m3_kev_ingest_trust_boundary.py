"""Offline regression tests for the M3 KEV integrity/provenance boundary.

All fixtures are synthetic. Passing these tests does not authenticate CISA.
"""
import hashlib
import unittest
from unittest.mock import patch

from ogde.core import SecurityError, canonical
from ogde.kev_ingest import ingest_kev_snapshot


def _digest(document):
    return hashlib.sha256(canonical(document)).hexdigest()


class KEVIngestTrustBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {
            "vulnerabilities": [
                {"cveID": "CVE-2026-12345", "dateAdded": "2026-11-01"}
            ]
        }

    def test_digest_mismatch_prevents_indexing_untrusted_snapshot(self):
        # No untrusted vulnerability rows should be interpreted before the
        # independently supplied digest has been checked.
        with patch("ogde.kev_ingest.kev_index", side_effect=AssertionError(
            "indexer must not run"
        )) as indexer:
            with self.assertRaisesRegex(SecurityError, "digest mismatch"):
                ingest_kev_snapshot(self.snapshot, expected_sha256="0" * 64)
            indexer.assert_not_called()

    def test_embedded_publisher_claim_cannot_authenticate_snapshot(self):
        forged = {
            **self.snapshot,
            "publisher_authenticated": True,
            "decision": "trusted",
            "publisher": "CISA",
            "signature_verified": True,
        }
        receipt = ingest_kev_snapshot(forged, expected_sha256=_digest(forged))
        self.assertIs(receipt["publisher_authenticated"], False)
        self.assertEqual(receipt["decision"], "human-review")
        self.assertTrue(receipt["integrity_verified"])

    def test_digest_format_is_strict_and_lowercase(self):
        for invalid in ("F" * 64, "f" * 63, "f" * 65, "f" * 64 + "\n", None, 123):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SecurityError):
                    ingest_kev_snapshot(self.snapshot, expected_sha256=invalid)

    def test_noncanonical_date_is_rejected_even_with_valid_digest(self):
        for date_added in ("20261101", "2026-11-1", "2026-02-30"):
            with self.subTest(date_added=date_added):
                doc = {"vulnerabilities": [
                    {"cveID": "CVE-2026-12345", "dateAdded": date_added}
                ]}
                with self.assertRaises(SecurityError):
                    ingest_kev_snapshot(doc, expected_sha256=_digest(doc))

    def test_oversized_snapshot_fails_closed_with_matching_digest(self):
        doc = {"vulnerabilities": [
            {"cveID": f"CVE-2026-{10000 + n}", "dateAdded": "2026-11-01"}
            for n in range(20001)
        ]}
        with self.assertRaisesRegex(SecurityError, "entry limit"):
            ingest_kev_snapshot(doc, expected_sha256=_digest(doc))


if __name__ == "__main__":
    unittest.main()
