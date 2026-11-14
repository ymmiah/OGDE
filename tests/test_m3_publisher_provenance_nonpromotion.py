"""M3 trust-boundary regression tests: operator claims never promote publisher trust."""

import unittest
from types import MappingProxyType

from ogde.publisher_provenance import assess_publisher_provenance


class PublisherProvenanceNonPromotionTests(unittest.TestCase):
    def test_absent_attestation_remains_untrusted(self):
        assessment = assess_publisher_provenance()
        self.assertEqual(assessment.decision, "human-review")
        self.assertEqual(assessment.reason, "independent-publisher-authentication-not-established")
        self.assertFalse(assessment.publisher_authenticated)
        self.assertFalse(assessment.operator_signature_verified)

    def test_self_asserted_authentication_cannot_promote_trust(self):
        attestations = (
            {},
            {"publisher_authenticated": True, "operator_signature_verified": True},
            {"publisher": "CISA", "verified": True, "trusted": True},
            {"signature": "claimed-valid", "digest": "0" * 64, "revision": 999999},
            MappingProxyType({"publisher_authenticated": True}),
        )
        for attestation in attestations:
            with self.subTest(attestation=repr(attestation)):
                result = assess_publisher_provenance(attestation).as_dict()
                self.assertIs(result["publisher_authenticated"], False)
                self.assertIs(result["operator_signature_verified"], False)
                self.assertEqual(result["decision"], "human-review")
                self.assertEqual(result["reason"], "independent-publisher-authentication-not-established")

    def test_invalid_attestation_type_rejected(self):
        for invalid in (True, "verified", ["verified"], 1):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TypeError):
                    assess_publisher_provenance(invalid)


if __name__ == "__main__":
    unittest.main()
