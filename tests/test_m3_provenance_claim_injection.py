"""Regression coverage for untrusted publisher-identity claims.

An operator's valid attestation cannot bootstrap publisher identity. These
checks intentionally do not require network access or any trust-anchor setup.
"""
import unittest
from types import MappingProxyType

from ogde.publisher_provenance import assess_publisher_provenance


class UntrustedPublisherClaimTests(unittest.TestCase):
    def test_nested_claims_cannot_promote_publisher(self):
        claims = {
            "publisher": "CISA",
            "publisher_authenticated": True,
            "provenance": {
                "verified": True,
                "trust_anchor": "owner-approved",
                "publisher_signature_verified": True,
            },
            "decision": "trusted",
        }
        assessment = assess_publisher_provenance(claims)
        self.assertIs(assessment.publisher_authenticated, False)
        self.assertEqual(assessment.decision, "human-review")
        self.assertEqual(assessment.reason, "independent-publisher-authentication-not-established")
        self.assertIs(assessment.operator_signature_verified, False)

    def test_readonly_mapping_claim_cannot_promote_publisher(self):
        claims = MappingProxyType({"publisher_authenticated": True, "decision": "trusted"})
        assessment = assess_publisher_provenance(claims)
        self.assertFalse(assessment.publisher_authenticated)
        self.assertEqual(assessment.decision, "human-review")

    def test_mutating_serialised_receipt_cannot_mutate_assessment(self):
        assessment = assess_publisher_provenance({"publisher_authenticated": True})
        receipt = assessment.as_dict()
        receipt["publisher_authenticated"] = True
        receipt["decision"] = "trusted"
        self.assertFalse(assessment.publisher_authenticated)
        self.assertEqual(assessment.decision, "human-review")


if __name__ == "__main__":
    unittest.main()
