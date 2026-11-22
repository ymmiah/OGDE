"""Offline trust-boundary regressions for local KEV ingestion.

An independently supplied matching digest proves byte integrity only.
Untrusted snapshot fields must never promote the receipt to authenticated.
"""
import hashlib
import unittest

from ogde.core import canonical
from ogde.kev_ingest import ingest_kev_snapshot


class KEVTrustBoundaryTests(unittest.TestCase):
    def _receipt(self, snapshot):
        digest = hashlib.sha256(canonical(snapshot)).hexdigest()
        return ingest_kev_snapshot(snapshot, expected_sha256=digest)

    def test_embedded_publisher_claim_cannot_authenticate(self):
        snapshot = {
            "publisher_authenticated": True,
            "decision": "trusted",
            "signature_verified": True,
            "vulnerabilities": [
                {"cveID": "CVE-2026-12345", "dateAdded": "2026-10-31"}
            ],
        }
        receipt = self._receipt(snapshot)
        self.assertTrue(receipt["integrity_verified"])
        self.assertIs(receipt["publisher_authenticated"], False)
        self.assertEqual(receipt["decision"], "human-review")
        self.assertNotIn("signature_verified", receipt)

    def test_embedded_digest_and_url_cannot_promote_trust(self):
        snapshot = {
            "source": "https://www.cisa.gov/",
            "sha256": "0" * 64,
            "verified": True,
            "vulnerabilities": [],
        }
        receipt = self._receipt(snapshot)
        self.assertIs(receipt["publisher_authenticated"], False)
        self.assertEqual(receipt["decision"], "human-review")
        self.assertEqual(receipt["entry_count"], 0)
        self.assertNotIn("verified", receipt)
        self.assertNotIn("source", receipt)

    def test_valid_digest_is_not_freshness_evidence(self):
        snapshot = {
            "dateReleased": "2020-01-01",
            "vulnerabilities": [
                {"cveID": "CVE-2020-12345", "dateAdded": "2020-01-01"}
            ],
        }
        receipt = self._receipt(snapshot)
        self.assertFalse(receipt["publisher_authenticated"])
        self.assertEqual(receipt["decision"], "human-review")
        self.assertTrue(any("freshness" in item for item in receipt["limitations"]))


if __name__ == "__main__":
    unittest.main()
