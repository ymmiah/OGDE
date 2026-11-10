"""Offline M3 publisher-authentication boundary regression tests."""

import unittest

from ogde.publisher_provenance import assess_publisher_provenance


class PublisherProvenanceTests(unittest.TestCase):
    def test_missing_proof_requires_review(self):
        result = assess_publisher_provenance()
        self.assertFalse(result.publisher_authenticated)
        self.assertEqual(result.decision, "human-review")

    def test_forged_publisher_claim_is_never_trusted(self):
        result = assess_publisher_provenance({
            "publisher_authenticated": True,
            "publisher": "CISA",
            "signer_id": "CISA",
            "decision": "trusted",
        })
        self.assertFalse(result.publisher_authenticated)
        self.assertFalse(result.operator_signature_verified)
        self.assertEqual(result.decision, "human-review")

    def test_operator_verified_flag_is_not_independent_proof(self):
        result = assess_publisher_provenance({"operator_signature_verified": True})
        self.assertFalse(result.publisher_authenticated)
        self.assertFalse(result.operator_signature_verified)

    def test_result_is_immutable(self):
        from dataclasses import FrozenInstanceError
        result = assess_publisher_provenance()
        with self.assertRaises(FrozenInstanceError):
            result.publisher_authenticated = True

    def test_invalid_input_rejected(self):
        with self.assertRaises(TypeError):
            assess_publisher_provenance("trusted")

    def test_serialisation_cannot_promote_trust(self):
        result = assess_publisher_provenance({"publisher_authenticated": True})
        self.assertIs(result.as_dict()["publisher_authenticated"], False)


if __name__ == "__main__":
    unittest.main()
