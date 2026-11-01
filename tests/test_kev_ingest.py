"""Synthetic offline KEV ingestion regression tests."""
import hashlib
import unittest
from ogde.core import SecurityError, canonical
from ogde.kev_ingest import ingest_kev_snapshot


class KEVIngestTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-31", "knownRansomwareCampaignUse": "Unknown"}]}
        self.digest = hashlib.sha256(canonical(self.snapshot)).hexdigest()

    def test_valid_snapshot_remains_untrusted_publisher(self):
        result = ingest_kev_snapshot(self.snapshot, expected_sha256=self.digest)
        self.assertTrue(result["integrity_verified"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertEqual(result["decision"], "human-review")
        self.assertEqual(result["kev_cves"], ["CVE-2026-12345"])

    def test_wrong_digest_rejected(self):
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(self.snapshot, expected_sha256="0" * 64)

    def test_duplicate_cve_rejected(self):
        doc = {"vulnerabilities": self.snapshot["vulnerabilities"] * 2}
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256=hashlib.sha256(canonical(doc)).hexdigest())

    def test_invalid_date_rejected(self):
        doc = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-02-30"}]}
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256=hashlib.sha256(canonical(doc)).hexdigest())

    def test_missing_date_rejected(self):
        doc = {"vulnerabilities": [{"cveID": "CVE-2026-12345"}]}
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256=hashlib.sha256(canonical(doc)).hexdigest())

    def test_invalid_digest_format_rejected(self):
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(self.snapshot, expected_sha256="ABC")


if __name__ == "__main__":
    unittest.main()
