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

    def test_in_memory_snapshot_over_10_mib_rejected_even_with_matching_digest(self):
        # Direct callers must have the same size boundary as read_json().
        doc = dict(self.snapshot)
        doc["padding"] = "x" * (10 * 1024 * 1024)
        digest = hashlib.sha256(canonical(doc)).hexdigest()
        with self.assertRaisesRegex(SecurityError, "10 MiB"):
            ingest_kev_snapshot(doc, expected_sha256=digest)

    def test_cyclic_snapshot_rejected_as_security_error(self):
        doc = {"vulnerabilities": []}
        doc["cycle"] = doc
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256="0" * 64)

    def test_excessively_nested_snapshot_rejected_as_security_error(self):
        doc = {"vulnerabilities": []}
        nested = doc
        for _ in range(1200):
            child = {}
            nested["child"] = child
            nested = child
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256="0" * 64)

    def test_malformed_ransomware_signal_rejected_even_with_matching_digest(self):
        for signal in ("known", "Yes", True, 1, [], {}):
            with self.subTest(signal=signal):
                doc = {"vulnerabilities": [{
                    "cveID": "CVE-2026-12345",
                    "dateAdded": "2026-10-31",
                    "knownRansomwareCampaignUse": signal,
                }]}
                digest = hashlib.sha256(canonical(doc)).hexdigest()
                with self.assertRaisesRegex(SecurityError, "ransomware campaign"):
                    ingest_kev_snapshot(doc, expected_sha256=digest)

    def test_known_ransomware_signal_preserved(self):
        from ogde.kev import kev_index
        self.assertFalse(kev_index(self.snapshot)["CVE-2026-12345"]["ransomware_campaign"])
        doc = {"vulnerabilities": [{
            "cveID": "CVE-2026-12345",
            "dateAdded": "2026-10-31",
            "knownRansomwareCampaignUse": "Known",
        }]}
        self.assertTrue(kev_index(doc)["CVE-2026-12345"]["ransomware_campaign"])

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


    def test_matching_digest_does_not_override_invalid_cve_schema(self):
        doc = {"vulnerabilities": [{"cveID": "not-a-cve", "dateAdded": "2026-10-31"}]}
        digest = hashlib.sha256(canonical(doc)).hexdigest()
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256=digest)

    def test_matching_digest_does_not_override_noncanonical_date(self):
        doc = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-1-2"}]}
        digest = hashlib.sha256(canonical(doc)).hexdigest()
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256=digest)

    def test_matching_digest_does_not_override_invalid_container(self):
        doc = {"vulnerabilities": {"CVE-2026-12345": {"dateAdded": "2026-10-31"}}}
        digest = hashlib.sha256(canonical(doc)).hexdigest()
        with self.assertRaises(SecurityError):
            ingest_kev_snapshot(doc, expected_sha256=digest)

if __name__ == "__main__":
    unittest.main()
