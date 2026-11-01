import unittest
from ogde.core import SecurityError
from ogde.kev_freshness import assess_kev_freshness


class FreshnessTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {"kind": "ogde-kev-ingestion-receipt",
                        "integrity_verified": True,
                        "publisher_authenticated": False,
                        "digest_sha256": "a" * 64}

    def assess(self, **kw):
        return assess_kev_freshness(self.receipt, snapshot_date="2026-10-25",
                                    as_of="2026-11-01", **kw)

    def test_boundary_within_policy(self):
        self.assertEqual(self.assess()["freshness"], "within-policy")

    def test_stale(self):
        self.assertEqual(self.assess(max_age_days=6)["freshness"], "stale")

    def test_future_date_rejected(self):
        with self.assertRaises(SecurityError):
            assess_kev_freshness(self.receipt, snapshot_date="2026-11-02", as_of="2026-11-01")

    def test_boolean_policy_rejected(self):
        with self.assertRaises(SecurityError):
            self.assess(max_age_days=True)

    def test_unverified_receipt_rejected(self):
        self.receipt["integrity_verified"] = False
        with self.assertRaises(SecurityError):
            self.assess()

    def test_claimed_publisher_authentication_rejected(self):
        self.receipt["publisher_authenticated"] = True
        with self.assertRaises(SecurityError):
            self.assess()

    def test_invalid_date_rejected(self):
        with self.assertRaises(SecurityError):
            assess_kev_freshness(self.receipt, snapshot_date="2026-02-30", as_of="2026-11-01")


if __name__ == "__main__":
    unittest.main()
