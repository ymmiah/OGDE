import copy
import unittest
from ogde.core import SecurityError
from ogde.kev_reconcile import reconcile_kev_findings


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {
            "kind": "ogde-kev-ingestion-receipt", "integrity_verified": True,
            "publisher_authenticated": False, "digest_sha256": "a" * 64,
            "kev_cves": ["CVE-2026-12345"], "entry_count": 1,
        }
        self.finding = {
            "schema_version": 1, "finding_id": "F-1", "confidence": "probable",
            "component": {"purl": "pkg:npm/demo@1.0.0", "name": "demo", "version": "1.0.0"},
            "vulnerability": {"id": "CVE-2026-12345", "severity": "high"},
            "signals": {"kev_listed": True, "epss": None, "internet_exposed": False},
            "affected": False,
            "evidence": [{"source": "local", "record_id": "test", "digest_sha256": "b" * 64}],
            "limitations": ["Synthetic test data."],
        }

    def run_reconciliation(self):
        return reconcile_kev_findings({"schema_version": 1, "findings": [self.finding]}, self.receipt)

    def test_matching_signal_and_no_mutation(self):
        original = copy.deepcopy(self.finding)
        result = self.run_reconciliation()
        self.assertTrue(result["annotations"][0]["signal_consistent"])
        self.assertEqual(result["inconsistent_signal_count"], 0)
        self.assertEqual(self.finding, original)
        self.assertEqual(result["decision"], "human-review")

    def test_conflicting_signal_is_flagged_not_rewritten(self):
        self.finding["signals"]["kev_listed"] = False
        result = self.run_reconciliation()
        self.assertEqual(result["inconsistent_signal_count"], 1)
        self.assertFalse(result["annotations"][0]["signal_consistent"])

    def test_missing_cve_is_flagged(self):
        self.finding["vulnerability"]["id"] = "CVE-2026-99999"
        result = self.run_reconciliation()
        self.assertEqual(result["inconsistent_signal_count"], 1)

    def test_unverified_receipt_rejected(self):
        self.receipt["integrity_verified"] = False
        with self.assertRaises(SecurityError):
            self.run_reconciliation()

    def test_bad_digest_rejected(self):
        self.receipt["digest_sha256"] = "broken"
        with self.assertRaises(SecurityError):
            self.run_reconciliation()

    def test_duplicate_cve_rejected(self):
        self.receipt["kev_cves"] *= 2
        self.receipt["entry_count"] = 2
        with self.assertRaises(SecurityError):
            self.run_reconciliation()

    def test_count_mismatch_rejected(self):
        self.receipt["entry_count"] = 2
        with self.assertRaises(SecurityError):
            self.run_reconciliation()

    def test_publisher_claim_rejected(self):
        self.receipt["publisher_authenticated"] = True
        with self.assertRaises(SecurityError):
            self.run_reconciliation()

    def test_empty_findings(self):
        result = reconcile_kev_findings({"schema_version": 1, "findings": []}, self.receipt)
        self.assertEqual(result["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
