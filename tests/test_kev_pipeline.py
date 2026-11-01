import hashlib
import unittest
from ogde.core import SecurityError, canonical
from ogde.kev_pipeline import review_kev_snapshot


class KevPipelineTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {"vulnerabilities": [
            {"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}
        ]}
        self.digest = hashlib.sha256(canonical(self.snapshot)).hexdigest()
        self.document = {"schema_version": 1, "findings": []}

    def run_pipeline(self, **kwargs):
        params = {"expected_sha256": self.digest, "snapshot_date": "2026-10-25",
                  "as_of": "2026-11-01"}
        params.update(kwargs)
        return review_kev_snapshot(self.snapshot, self.document, **params)

    def test_fresh_and_consistent_requires_human_review(self):
        result = self.run_pipeline()
        self.assertEqual(result["review_status"], "requires-human-review")
        self.assertEqual(result["issues"], [])
        self.assertFalse(result["publisher_authenticated"])

    def test_stale_snapshot_blocks(self):
        result = self.run_pipeline(max_age_days=6)
        self.assertEqual(result["review_status"], "blocked")
        self.assertIn("stale-snapshot", result["issues"])

    def test_wrong_digest_fails_closed(self):
        with self.assertRaises(SecurityError):
            self.run_pipeline(expected_sha256="0" * 64)

    def test_future_snapshot_date_fails_closed(self):
        with self.assertRaises(SecurityError):
            self.run_pipeline(snapshot_date="2026-11-02")

    def test_bad_findings_contract_fails_closed(self):
        self.document["findings"] = [{"invalid": True}]
        with self.assertRaises(SecurityError):
            self.run_pipeline()


if __name__ == "__main__":
    unittest.main()
