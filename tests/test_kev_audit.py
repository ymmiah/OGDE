import copy
import unittest
from ogde.core import SecurityError
from ogde.kev_audit import build_kev_audit_manifest


class AuditManifestTests(unittest.TestCase):
    def setUp(self):
        digest = "a" * 64
        self.review = {
            "kind": "ogde-kev-review-pipeline", "digest_sha256": digest,
            "publisher_authenticated": False, "decision": "human-review",
            "review_status": "requires-human-review", "issues": [],
            "freshness": {"kind": "ogde-kev-freshness-assessment", "digest_sha256": digest,
                          "age_days": 2, "max_age_days": 7, "freshness": "within-policy"},
            "reconciliation": {"kind": "ogde-kev-local-reconciliation",
                               "snapshot_digest_sha256": digest, "finding_count": 1,
                               "inconsistent_signal_count": 0,
                               "annotations": [{"signal_consistent": True}]},
        }

    def test_reproducible_and_does_not_mutate(self):
        original = copy.deepcopy(self.review)
        a = build_kev_audit_manifest(self.review)
        self.assertEqual(a, build_kev_audit_manifest(self.review))
        self.assertEqual(self.review, original)
        self.assertEqual(len(a["manifest_sha256"]), 64)

    def test_no_finding_identifiers_in_manifest(self):
        self.review["reconciliation"]["annotations"][0]["finding_id"] = "private-asset"
        self.assertNotIn("private-asset", str(build_kev_audit_manifest(self.review)))

    def test_stale_requires_block(self):
        self.review["freshness"].update(age_days=8, freshness="stale")
        with self.assertRaises(SecurityError):
            build_kev_audit_manifest(self.review)
        self.review["issues"] = ["stale-snapshot"]
        self.review["review_status"] = "blocked"
        self.assertEqual(build_kev_audit_manifest(self.review)["review_status"], "blocked")

    def test_inconsistent_signal_requires_block(self):
        self.review["reconciliation"]["annotations"][0]["signal_consistent"] = False
        self.review["reconciliation"]["inconsistent_signal_count"] = 1
        with self.assertRaises(SecurityError):
            build_kev_audit_manifest(self.review)

    def test_mismatched_digest_rejected(self):
        self.review["freshness"]["digest_sha256"] = "b" * 64
        with self.assertRaises(SecurityError):
            build_kev_audit_manifest(self.review)

    def test_boolean_count_rejected(self):
        self.review["reconciliation"]["finding_count"] = True
        with self.assertRaises(SecurityError):
            build_kev_audit_manifest(self.review)

    def test_duplicate_issues_rejected(self):
        self.review["issues"] = ["stale-snapshot", "stale-snapshot"]
        self.review["review_status"] = "blocked"
        with self.assertRaises(SecurityError):
            build_kev_audit_manifest(self.review)


if __name__ == "__main__":
    unittest.main()
